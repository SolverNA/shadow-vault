/**
 * Интеграционные тесты для ShadowVaultManager.
 *
 * Архитектура:
 *   originalRoot/<name>.enc  — зашифрованные файлы
 *   shadowRoot/<name>        — расшифрованные файлы (рабочая копия)
 *
 * MockAdapter симулирует оригинальный адаптер Obsidian над originalRoot.
 */

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import * as fs from "fs";
import * as fsp from "fs/promises";
import * as os from "os";
import * as nodePath from "path";
import { ShadowVaultManager } from "../src/shadow-vault-manager";
import { CryptoEngine } from "../src/crypto-engine";
import { IDataAdapter, AdapterStat, DataWriteOptions, ListedFiles } from "../src/adapter-types";

// ─────────────────────────────────────────────
// MockAdapter — оригинальный адаптер Obsidian (работает с originalRoot напрямую)
// ─────────────────────────────────────────────
class MockAdapter implements IDataAdapter {
  constructor(public readonly basePath: string) {}

  getBasePath(): string { return this.basePath; }
  getResourcePath(p: string): string { return this.abs(p); }

  async read(p: string): Promise<string> {
    return fsp.readFile(this.abs(p), "utf8");
  }
  async readBinary(p: string): Promise<ArrayBuffer> {
    const buf = await fsp.readFile(this.abs(p));
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  async write(p: string, data: string): Promise<void> {
    await fsp.mkdir(nodePath.dirname(this.abs(p)), { recursive: true });
    await fsp.writeFile(this.abs(p), data, "utf8");
  }
  async writeBinary(p: string, data: ArrayBuffer): Promise<void> {
    await fsp.mkdir(nodePath.dirname(this.abs(p)), { recursive: true });
    await fsp.writeFile(this.abs(p), Buffer.from(data));
  }
  async append(p: string, data: string): Promise<void> {
    await fsp.appendFile(this.abs(p), data, "utf8");
  }
  async process(p: string, fn: (d: string) => string): Promise<string> {
    const cur = await this.read(p);
    const result = fn(cur);
    await this.write(p, result);
    return result;
  }
  async exists(p: string): Promise<boolean> {
    try { await fsp.access(this.abs(p)); return true; } catch { return false; }
  }
  async stat(p: string): Promise<AdapterStat | null> {
    try {
      const s = await fsp.stat(this.abs(p));
      return { type: s.isDirectory() ? "folder" : "file", ctime: s.ctimeMs, mtime: s.mtimeMs, size: s.size };
    } catch { return null; }
  }
  async list(p: string): Promise<ListedFiles> {
    const abs = this.abs(p);
    try {
      const entries = await fsp.readdir(abs, { withFileTypes: true });
      const prefix = p ? p + "/" : "";
      return {
        files:   entries.filter(e => e.isFile()).map(e => prefix + e.name),
        folders: entries.filter(e => e.isDirectory()).map(e => prefix + e.name),
      };
    } catch { return { files: [], folders: [] }; }
  }
  async mkdir(p: string): Promise<void> {
    await fsp.mkdir(this.abs(p), { recursive: true });
  }
  async remove(p: string): Promise<void> {
    await fsp.unlink(this.abs(p));
  }
  async rename(p: string, np: string): Promise<void> {
    await fsp.rename(this.abs(p), this.abs(np));
  }
  async copy(p: string, np: string): Promise<void> {
    await fsp.copyFile(this.abs(p), this.abs(np));
  }
  async trashSystem(p: string): Promise<boolean> {
    await fsp.unlink(this.abs(p)).catch(() => undefined);
    return true;
  }
  async trashLocal(p: string): Promise<void> {
    await fsp.unlink(this.abs(p)).catch(() => undefined);
  }

  private abs(p: string): string {
    return nodePath.join(this.basePath, ...p.split("/"));
  }
}

// ─────────────────────────────────────────────
// Фабрика тестового окружения
// ─────────────────────────────────────────────
interface TestEnv {
  engine:   CryptoEngine;
  manager:  ShadowVaultManager;
  adapter:  MockAdapter;
  origRoot: string;
  shadowRoot: string;
  cleanup:  () => void;
}

async function makeEnv(): Promise<TestEnv> {
  const base = fs.mkdtempSync(nodePath.join(os.tmpdir(), "sv-test-"));
  const origRoot   = nodePath.join(base, "original");
  const shadowRoot = nodePath.join(base, "shadow");
  fs.mkdirSync(origRoot, { recursive: true });

  const engine = new CryptoEngine();
  await engine.deriveKey("test@test.local", "test-password");

  const manager = new ShadowVaultManager(engine, origRoot, shadowRoot);
  await manager.initialize();

  const adapter = new MockAdapter(origRoot);
  manager.patch(adapter);

  return {
    engine,
    manager,
    adapter,
    origRoot,
    shadowRoot,
    cleanup: () => {
      engine.destroy();
      fs.rmSync(base, { recursive: true, force: true });
    },
  };
}

// ─────────────────────────────────────────────
// Утилиты
// ─────────────────────────────────────────────

/**
 * Записывает зашифрованный файл в originalRoot как <relPath>.enc
 * (симулирует файл, уже прошедший шифрование — нормальное состояние хранилища).
 */
async function writeEncrypted(env: TestEnv, relPath: string, plaintext: string): Promise<void> {
  const encPath = nodePath.join(env.origRoot, ...relPath.split("/")) + ".enc";
  await fsp.mkdir(nodePath.dirname(encPath), { recursive: true });
  const encrypted = env.engine.encryptBuffer(Buffer.from(plaintext, "utf8"));
  await fsp.writeFile(encPath, encrypted);
}

// ─────────────────────────────────────────────
// Инициализация и пути
// ─────────────────────────────────────────────

describe("ShadowVaultManager — инициализация и пути", () => {
  it("создаёт директорию shadowRoot при initialize()", async () => {
    const base = fs.mkdtempSync(nodePath.join(os.tmpdir(), "sv-init-"));
    const origRoot   = nodePath.join(base, "orig");
    const shadowRoot = nodePath.join(base, "shadow-new");
    fs.mkdirSync(origRoot);

    const engine = new CryptoEngine();
    await engine.deriveKey("test@test.local", "pwd");
    const manager = new ShadowVaultManager(engine, origRoot, shadowRoot);
    await manager.initialize();

    expect(fs.existsSync(shadowRoot)).toBe(true);
    engine.destroy();
    fs.rmSync(base, { recursive: true, force: true });
  });

  it("shadowAbs и originalAbs корректно строят абсолютные пути", async () => {
    const env = await makeEnv();
    try {
      expect(env.manager.shadowAbs("Notes/MyNote.md")).toBe(
        nodePath.join(env.shadowRoot, "Notes", "MyNote.md")
      );
      expect(env.manager.originalAbs("Notes/MyNote.md")).toBe(
        nodePath.join(env.origRoot, "Notes", "MyNote.md")
      );
      // originalEncAbs добавляет .enc
      expect(env.manager.originalEncAbs("Notes/MyNote.md")).toBe(
        nodePath.join(env.origRoot, "Notes", "MyNote.md") + ".enc"
      );
    } finally { env.cleanup(); }
  });

  it("isBypassPath: .obsidian/* → true, остальное → false", async () => {
    const env = await makeEnv();
    try {
      expect(env.manager.isBypassPath("")).toBe(true);
      expect(env.manager.isBypassPath(".obsidian")).toBe(true);
      expect(env.manager.isBypassPath(".obsidian/plugins/my-plugin/data.json")).toBe(true);
      expect(env.manager.isBypassPath("Notes/MyNote.md")).toBe(false);
      expect(env.manager.isBypassPath("Attachments/image.png")).toBe(false);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты чтения
// ─────────────────────────────────────────────

describe("ShadowVaultManager — read()", () => {
  it("читает уже зашифрованный файл: расшифровывает и возвращает plaintext", async () => {
    const env = await makeEnv();
    try {
      // В original: note.md.enc
      await writeEncrypted(env, "note.md", "# Hello\n\nSecret content.");
      const result = await env.adapter.read("note.md");
      expect(result).toBe("# Hello\n\nSecret content.");
    } finally { env.cleanup(); }
  });

  it("повторное read() берёт данные из shadow-кэша (кэш-хит)", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "cached content");
      await env.adapter.read("note.md"); // первый read → decryptStream → shadow/note.md

      // Удаляем .enc оригинал — повторный read() должен брать из shadow
      await fsp.unlink(nodePath.join(env.origRoot, "note.md.enc"));
      const result = await env.adapter.read("note.md");
      expect(result).toBe("cached content");
    } finally { env.cleanup(); }
  });

  it("читает вложенный файл (Notes/Sub/deep.md)", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "Notes/Sub/deep.md", "deep content");
      const result = await env.adapter.read("Notes/Sub/deep.md");
      expect(result).toBe("deep content");
    } finally { env.cleanup(); }
  });

  it("бросает ошибку при чтении несуществующего файла", async () => {
    const env = await makeEnv();
    try {
      await expect(env.adapter.read("nonexistent.md")).rejects.toThrow();
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты записи
// ─────────────────────────────────────────────

describe("ShadowVaultManager — write()", () => {
  it("write() создаёт plaintext в shadow и .enc файл в original", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("new-note.md", "Hello, vault!");

      // Теневое хранилище: plaintext
      const shadowContent = await fsp.readFile(
        nodePath.join(env.shadowRoot, "new-note.md"), "utf8"
      );
      expect(shadowContent).toBe("Hello, vault!");

      // Оригинальное хранилище: зашифрованный файл с суффиксом .enc
      const encBuf = await fsp.readFile(nodePath.join(env.origRoot, "new-note.md.enc"));
      expect(encBuf.length).toBeGreaterThan(28); // IV(12) + AuthTag(16) + данные
    } finally { env.cleanup(); }
  });

  it("зашифрованный .enc файл в original можно расшифровать обратно", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("secret.md", "Top secret");

      const encBuf = await fsp.readFile(nodePath.join(env.origRoot, "secret.md.enc"));
      const decBuf = env.engine.decryptBuffer(encBuf);
      expect(decBuf.toString("utf8")).toBe("Top secret");
    } finally { env.cleanup(); }
  });

  it("write() создаёт промежуточные директории", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("Projects/Alpha/notes.md", "project notes");

      expect(fs.existsSync(nodePath.join(env.shadowRoot, "Projects", "Alpha", "notes.md"))).toBe(true);
      expect(fs.existsSync(nodePath.join(env.origRoot,   "Projects", "Alpha", "notes.md.enc"))).toBe(true);
    } finally { env.cleanup(); }
  });

  it("перезапись файла обновляет оба хранилища", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("note.md", "version 1");
      await env.adapter.write("note.md", "version 2");

      const shadowContent = await fsp.readFile(
        nodePath.join(env.shadowRoot, "note.md"), "utf8"
      );
      expect(shadowContent).toBe("version 2");

      const encBuf = await fsp.readFile(nodePath.join(env.origRoot, "note.md.enc"));
      const dec = env.engine.decryptBuffer(encBuf);
      expect(dec.toString("utf8")).toBe("version 2");
    } finally { env.cleanup(); }
  });

  it("атомарность: нет .shadowtmp файла после успешной записи", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("atomic.md", "data");
      // Временный файл atomicWrite: note.md.enc.shadowtmp
      const tmpPath = nodePath.join(env.origRoot, "atomic.md.enc.shadowtmp");
      expect(fs.existsSync(tmpPath)).toBe(false);
    } finally { env.cleanup(); }
  });

  it("H1: ошибка шифрования при write НЕ перезаписывает shadow и пробрасывается", async () => {
    const env = await makeEnv();
    try {
      // Первичная успешная запись
      await env.adapter.write("guard.md", "GOOD");
      const shadowPath = nodePath.join(env.shadowRoot, "guard.md");
      expect(await fsp.readFile(shadowPath, "utf8")).toBe("GOOD");

      // Ломаем шифрование: encryptBuffer бросит (assertUnlocked)
      const orig = env.engine.encryptBuffer.bind(env.engine);
      (env.engine as unknown as { encryptBuffer: () => never }).encryptBuffer = () => {
        throw new Error("simulated encrypt failure");
      };

      await expect(env.adapter.write("guard.md", "BAD")).rejects.toThrow(
        "simulated encrypt failure"
      );

      // shadow НЕ перезаписан новыми данными
      expect(await fsp.readFile(shadowPath, "utf8")).toBe("GOOD");
      // .enc тоже остался старым
      const enc = await fsp.readFile(nodePath.join(env.origRoot, "guard.md.enc"));
      (env.engine as unknown as { encryptBuffer: typeof orig }).encryptBuffer = orig;
      expect(env.engine.decryptBuffer(enc).toString("utf8")).toBe("GOOD");
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты append()
// ─────────────────────────────────────────────

describe("ShadowVaultManager — append()", () => {
  it("append() добавляет к существующему зашифрованному файлу", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "log.md", "line 1\n");
      await env.adapter.append("log.md", "line 2\n");

      const result = await env.adapter.read("log.md");
      expect(result).toBe("line 1\nline 2\n");
    } finally { env.cleanup(); }
  });

  it("append() к несуществующему файлу создаёт его", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.append("new-log.md", "first line\n");
      const shadowPath = nodePath.join(env.shadowRoot, "new-log.md");
      const content = await fsp.readFile(shadowPath, "utf8");
      expect(content).toBe("first line\n");
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты process()
// ─────────────────────────────────────────────

describe("ShadowVaultManager — process()", () => {
  it("process() читает, трансформирует и сохраняет", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "hello");
      const result = await env.adapter.process("note.md", (s) => s.toUpperCase());

      expect(result).toBe("HELLO");
      const readBack = await env.adapter.read("note.md");
      expect(readBack).toBe("HELLO");
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты exists() и stat()
// ─────────────────────────────────────────────

describe("ShadowVaultManager — exists() и stat()", () => {
  it("exists() возвращает true для файла с .enc в original", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "content");
      // .enc файл существует → exists("note.md") → true
      expect(await env.adapter.exists("note.md")).toBe(true);
    } finally { env.cleanup(); }
  });

  it("exists() возвращает false для несуществующего файла", async () => {
    const env = await makeEnv();
    try {
      expect(await env.adapter.exists("ghost.md")).toBe(false);
    } finally { env.cleanup(); }
  });

  it("stat() возвращает корректный тип и mtime", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "test");
      const stat = await env.adapter.stat("note.md");

      expect(stat).not.toBeNull();
      expect(stat!.type).toBe("file");
      expect(stat!.mtime).toBeGreaterThan(0);
    } finally { env.cleanup(); }
  });

  it("stat() компенсирует заголовок шифрования в размере файла", async () => {
    const env = await makeEnv();
    try {
      const text = "12345"; // 5 байт
      await writeEncrypted(env, "sized.md", text);
      const stat = await env.adapter.stat("sized.md");
      // Размер должен быть 5 (без 33 байт служебных данных контейнера v2)
      expect(stat!.size).toBe(5);
    } finally { env.cleanup(); }
  });

  it("stat() для chunked .enc даёт корректный размер plaintext (не искажён)", async () => {
    const env = await makeEnv();
    try {
      // Создаём plaintext > 4 МБ → encryptStream пишет chunked (0x03)
      const plainSize = 5 * 1024 * 1024 + 123;
      const srcPlain = nodePath.join(env.origRoot, "big.src");
      await fsp.writeFile(srcPlain, Buffer.alloc(plainSize, 0x61));
      const encPath = nodePath.join(env.origRoot, "big.md.enc");
      await env.engine.encryptStream(srcPlain, encPath);
      await fsp.unlink(srcPlain);

      const stat = await env.adapter.stat("big.md");
      // Точный размер plaintext (а не грубо .enc − 33)
      expect(stat!.size).toBe(plainSize);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты list()
// ─────────────────────────────────────────────

describe("ShadowVaultManager — list()", () => {
  it("list() возвращает файлы из original хранилища (без суффикса .enc)", async () => {
    const env = await makeEnv();
    try {
      // В original: a.md.enc, b.md.enc
      await writeEncrypted(env, "a.md", "A");
      await writeEncrypted(env, "b.md", "B");
      fs.mkdirSync(nodePath.join(env.origRoot, "Notes"));

      const result = await env.adapter.list("");
      // list() снимает .enc суффикс → Obsidian видит a.md, b.md
      expect(result.files).toContain("a.md");
      expect(result.files).toContain("b.md");
      expect(result.folders).toContain("Notes");
    } finally { env.cleanup(); }
  });

  it("list() не показывает сырые .enc файлы (только декодированные имена)", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "content");
      const result = await env.adapter.list("");
      expect(result.files).not.toContain("note.md.enc");
      expect(result.files).toContain("note.md");
    } finally { env.cleanup(); }
  });

  it("list() скрывает .tmp и .shadowtmp файлы", async () => {
    const env = await makeEnv();
    try {
      // Создаём "мусорные" временные файлы напрямую
      await fsp.writeFile(nodePath.join(env.origRoot, "note.md.enc.tmp"), "garbage");
      await fsp.writeFile(nodePath.join(env.origRoot, "note.md.enc.shadowtmp"), "garbage");
      await writeEncrypted(env, "note.md", "content");

      const result = await env.adapter.list("");
      expect(result.files).toContain("note.md");
      expect(result.files).not.toContain("note.md.enc.tmp");
      expect(result.files).not.toContain("note.md.enc.shadowtmp");
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты rename() и remove()
// ─────────────────────────────────────────────

describe("ShadowVaultManager — rename() и remove()", () => {
  it("rename() переименовывает в обоих хранилищах", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("old.md", "content");
      await env.adapter.rename("old.md", "new.md");

      expect(await env.adapter.exists("old.md")).toBe(false);
      expect(await env.adapter.exists("new.md")).toBe(true);

      const result = await env.adapter.read("new.md");
      expect(result).toBe("content");
    } finally { env.cleanup(); }
  });

  it("rename() переносит .enc файл в original", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("old.md", "data");
      await env.adapter.rename("old.md", "new.md");

      expect(fs.existsSync(nodePath.join(env.origRoot, "old.md.enc"))).toBe(false);
      expect(fs.existsSync(nodePath.join(env.origRoot, "new.md.enc"))).toBe(true);
    } finally { env.cleanup(); }
  });

  it("remove() удаляет из обоих хранилищ (.enc в original, plaintext в shadow)", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("to-delete.md", "bye");
      await env.adapter.remove("to-delete.md");

      // .enc удалён из original
      expect(fs.existsSync(nodePath.join(env.origRoot, "to-delete.md.enc"))).toBe(false);
      // plaintext удалён из shadow
      expect(fs.existsSync(nodePath.join(env.shadowRoot, "to-delete.md"))).toBe(false);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты bypass (.obsidian)
// ─────────────────────────────────────────────

describe("ShadowVaultManager — bypass для .obsidian", () => {
  it("write() к .obsidian пишет незашифрованный файл в original (без .enc)", async () => {
    const env = await makeEnv();
    try {
      fs.mkdirSync(nodePath.join(env.origRoot, ".obsidian"), { recursive: true });
      await env.adapter.write(".obsidian/app.json", '{"theme":"dark"}');

      const content = fs.readFileSync(
        nodePath.join(env.origRoot, ".obsidian", "app.json"), "utf8"
      );
      expect(content).toBe('{"theme":"dark"}');
      expect(fs.existsSync(nodePath.join(env.shadowRoot, ".obsidian"))).toBe(false);
    } finally { env.cleanup(); }
  });

  it("read() из .obsidian возвращает незашифрованный конфиг", async () => {
    const env = await makeEnv();
    try {
      const obsidianDir = nodePath.join(env.origRoot, ".obsidian");
      fs.mkdirSync(obsidianDir, { recursive: true });
      fs.writeFileSync(nodePath.join(obsidianDir, "app.json"), '{"font":"mono"}');

      const result = await env.adapter.read(".obsidian/app.json");
      expect(result).toBe('{"font":"mono"}');
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты unpatch()
// ─────────────────────────────────────────────

describe("ShadowVaultManager — unpatch()", () => {
  it("после unpatch() адаптер читает raw файлы из original (note.md.enc не читается как текст)", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("note.md", "secret");
      env.manager.unpatch(env.adapter);

      // После снятия патча: в original есть только note.md.enc (не note.md)
      // Оригинальный адаптер ищет note.md → файла нет → throw
      await expect(env.adapter.read("note.md")).rejects.toThrow();

      // .enc файл существует
      expect(fs.existsSync(nodePath.join(env.origRoot, "note.md.enc"))).toBe(true);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты миграции (encryptAllExisting)
// ─────────────────────────────────────────────

describe("ShadowVaultManager — encryptAllExisting() (миграция)", () => {
  it("шифрует незашифрованные файлы и удаляет оригиналы", async () => {
    const env = await makeEnv();
    try {
      // Пишем plaintext напрямую (как будто vault существовал до плагина)
      await fsp.writeFile(nodePath.join(env.origRoot, "plain.md"), "plaintext content");

      expect(await env.manager.hasPendingMigration()).toBe(true);

      await env.manager.encryptAllExisting();

      // plain.md удалён, plain.md.enc создан
      expect(fs.existsSync(nodePath.join(env.origRoot, "plain.md"))).toBe(false);
      expect(fs.existsSync(nodePath.join(env.origRoot, "plain.md.enc"))).toBe(true);

      // .enc расшифровывается корректно
      const encBuf = await fsp.readFile(nodePath.join(env.origRoot, "plain.md.enc"));
      const dec = env.engine.decryptBuffer(encBuf);
      expect(dec.toString("utf8")).toBe("plaintext content");

      expect(await env.manager.hasPendingMigration()).toBe(false);
    } finally { env.cleanup(); }
  });

  it("hasPendingMigration() = false когда все файлы зашифрованы", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "content");
      expect(await env.manager.hasPendingMigration()).toBe(false);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// mount / unmount
// ─────────────────────────────────────────────

describe("ShadowVaultManager — mount / unmount", () => {
  it("mount() подменяет basePath адаптера на shadowRoot", async () => {
    const env = await makeEnv();
    try {
      const before = (env.adapter as unknown as { basePath: string }).basePath;
      expect(before).toBe(env.origRoot);

      env.manager.mount(env.adapter);
      const after = (env.adapter as unknown as { basePath: string }).basePath;
      expect(after).toBe(env.shadowRoot);

      // getBasePath тоже возвращает shadow
      expect(env.adapter.getBasePath()).toBe(env.shadowRoot);
    } finally { env.cleanup(); }
  });

  it("getResourcePath после mount указывает на shadow (а не на оригинал)", async () => {
    const env = await makeEnv();
    try {
      env.manager.mount(env.adapter);
      const url = env.adapter.getResourcePath("img.png");
      expect(url).toContain(env.shadowRoot);
      expect(url).not.toContain(env.origRoot);
    } finally { env.cleanup(); }
  });

  it("unmount() возвращает basePath к исходному значению", async () => {
    const env = await makeEnv();
    try {
      env.manager.mount(env.adapter);
      env.manager.unmount(env.adapter);
      expect((env.adapter as unknown as { basePath: string }).basePath).toBe(env.origRoot);
      expect(env.adapter.getBasePath()).toBe(env.origRoot);
    } finally { env.cleanup(); }
  });

  it("mount() идемпотентен — повторный вызов не ломает состояние", async () => {
    const env = await makeEnv();
    try {
      env.manager.mount(env.adapter);
      env.manager.mount(env.adapter);
      expect((env.adapter as unknown as { basePath: string }).basePath).toBe(env.shadowRoot);

      env.manager.unmount(env.adapter);
      expect((env.adapter as unknown as { basePath: string }).basePath).toBe(env.origRoot);
    } finally { env.cleanup(); }
  });

  it("unmount без предыдущего mount: no-op", async () => {
    const env = await makeEnv();
    try {
      const before = (env.adapter as unknown as { basePath: string }).basePath;
      env.manager.unmount(env.adapter);
      expect((env.adapter as unknown as { basePath: string }).basePath).toBe(before);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// setupObsidianSymlink
// ─────────────────────────────────────────────

describe("ShadowVaultManager — setupObsidianSymlink", () => {
  it("создаёт symlink shadow/.obsidian → original/.obsidian", async () => {
    const env = await makeEnv();
    try {
      // .obsidian должен существовать в оригинале до setupObsidianSymlink
      const origConfig = nodePath.join(env.origRoot, ".obsidian");
      fs.mkdirSync(origConfig);
      fs.writeFileSync(nodePath.join(origConfig, "appearance.json"), "{}");

      await env.manager.setupObsidianSymlink();

      const shadowConfig = nodePath.join(env.shadowRoot, ".obsidian");
      const lst = fs.lstatSync(shadowConfig);
      expect(lst.isSymbolicLink()).toBe(true);

      // Через симлинк виден контент оригинала
      expect(fs.readFileSync(nodePath.join(shadowConfig, "appearance.json"), "utf8")).toBe("{}");
    } finally { env.cleanup(); }
  });

  it("если в shadow была обычная папка .obsidian — заменяет на symlink", async () => {
    const env = await makeEnv();
    try {
      const shadowConfig = nodePath.join(env.shadowRoot, ".obsidian");
      fs.mkdirSync(shadowConfig);
      fs.writeFileSync(nodePath.join(shadowConfig, "stale.json"), "old");

      await env.manager.setupObsidianSymlink();

      const lst = fs.lstatSync(shadowConfig);
      expect(lst.isSymbolicLink()).toBe(true);
    } finally { env.cleanup(); }
  });

  it("teardownObsidianSymlink снимает симлинк, не удаляет данные оригинала", async () => {
    const env = await makeEnv();
    try {
      const origConfig = nodePath.join(env.origRoot, ".obsidian");
      fs.mkdirSync(origConfig);
      fs.writeFileSync(nodePath.join(origConfig, "data.json"), "x");

      await env.manager.setupObsidianSymlink();
      await env.manager.teardownObsidianSymlink();

      expect(fs.existsSync(nodePath.join(env.shadowRoot, ".obsidian"))).toBe(false);
      // Оригинал не тронут
      expect(fs.readFileSync(nodePath.join(origConfig, "data.json"), "utf8")).toBe("x");
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// decryptAllToShadow
// ─────────────────────────────────────────────

describe("ShadowVaultManager — decryptAllToShadow", () => {
  it("расшифровывает все .enc файлы в shadow с правильным контентом", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "alpha");
      await writeEncrypted(env, "b.md", "beta");
      await writeEncrypted(env, "folder/c.md", "gamma");

      const result = await env.manager.decryptAllToShadow();

      expect(result.failed).toHaveLength(0);
      expect(result.decrypted.sort()).toEqual(["a.md", "b.md", "folder/c.md"]);

      // Контент в shadow корректный
      expect(fs.readFileSync(nodePath.join(env.shadowRoot, "a.md"), "utf8")).toBe("alpha");
      expect(fs.readFileSync(nodePath.join(env.shadowRoot, "b.md"), "utf8")).toBe("beta");
      expect(fs.readFileSync(nodePath.join(env.shadowRoot, "folder/c.md"), "utf8")).toBe("gamma");
    } finally { env.cleanup(); }
  });

  it("прогресс-колбэк вызывается с (done, total, current)", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "1");
      await writeEncrypted(env, "b.md", "2");
      await writeEncrypted(env, "c.md", "3");

      const calls: Array<{ done: number; total: number }> = [];
      const result = await env.manager.decryptAllToShadow((done, total) => {
        calls.push({ done, total });
      });

      expect(result.decrypted.length).toBe(3);
      // Финальный колбэк всегда (total, total)
      const last = calls[calls.length - 1];
      expect(last.done).toBe(3);
      expect(last.total).toBe(3);
    } finally { env.cleanup(); }
  });

  it("файл с битым шифрованием попадает в failed, остальные продолжают", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "good.md", "ok");
      // Битый .enc — заменяем на мусор после шифрования
      await writeEncrypted(env, "bad.md", "x");
      const badPath = nodePath.join(env.origRoot, "bad.md.enc");
      fs.writeFileSync(badPath, Buffer.from([0x00, 0x01, 0x02])); // меньше IV+AuthTag

      const result = await env.manager.decryptAllToShadow();

      expect(result.decrypted).toContain("good.md");
      expect(result.failed.map(f => f.path)).toContain("bad.md");
    } finally { env.cleanup(); }
  });

  it("пустое хранилище: возвращает пустые списки без ошибок", async () => {
    const env = await makeEnv();
    try {
      const result = await env.manager.decryptAllToShadow();
      expect(result.decrypted).toHaveLength(0);
      expect(result.failed).toHaveLength(0);
    } finally { env.cleanup(); }
  });

  it("идемпотентно: повторный вызов не ломает уже расшифрованные файлы", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "content");

      await env.manager.decryptAllToShadow();
      const firstStat = fs.statSync(nodePath.join(env.shadowRoot, "note.md"));

      await new Promise(r => setTimeout(r, 50));
      await env.manager.decryptAllToShadow();
      const secondStat = fs.statSync(nodePath.join(env.shadowRoot, "note.md"));

      // mtime не должен измениться (cache hit в ensureDecrypted)
      expect(secondStat.mtimeMs).toBe(firstStat.mtimeMs);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// encryptShadowChangesToOriginal (verify-back)
// ─────────────────────────────────────────────

describe("ShadowVaultManager — encryptShadowChangesToOriginal", () => {
  it("шифрует только изменённые в shadow файлы (побайтовое сравнение)", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "unchanged.md", "same");
      await writeEncrypted(env, "changed.md", "old");
      await env.manager.decryptAllToShadow();

      // Меняем только один файл в shadow
      fs.writeFileSync(nodePath.join(env.shadowRoot, "changed.md"), "NEW");

      const result = await env.manager.encryptShadowChangesToOriginal();

      expect(result.encrypted).toEqual(["changed.md"]);
      expect(result.failed).toHaveLength(0);

      // Проверяем что .enc оригинала действительно содержит новый контент
      const encBuf = fs.readFileSync(nodePath.join(env.origRoot, "changed.md.enc"));
      const plain = env.engine.decryptBuffer(encBuf);
      expect(plain.toString("utf8")).toBe("NEW");

      // Unchanged.md.enc не перешифровался — старый mtime
      const unchEnc = fs.readFileSync(nodePath.join(env.origRoot, "unchanged.md.enc"));
      const unchPlain = env.engine.decryptBuffer(unchEnc);
      expect(unchPlain.toString("utf8")).toBe("same");
    } finally { env.cleanup(); }
  });

  it("новый файл в shadow (без оригинала): шифрует и кладёт в оригинал", async () => {
    const env = await makeEnv();
    try {
      // Имитируем что плагин создал файл — есть только в shadow
      fs.mkdirSync(env.shadowRoot, { recursive: true });
      fs.writeFileSync(nodePath.join(env.shadowRoot, "fresh.md"), "brand new");

      const result = await env.manager.encryptShadowChangesToOriginal();
      expect(result.encrypted).toEqual(["fresh.md"]);

      const encBuf = fs.readFileSync(nodePath.join(env.origRoot, "fresh.md.enc"));
      expect(env.engine.decryptBuffer(encBuf).toString("utf8")).toBe("brand new");
    } finally { env.cleanup(); }
  });

  it("не оставляет .enc.bak / .enc.new после успешной записи", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "doc.md", "original");
      await env.manager.decryptAllToShadow();
      fs.writeFileSync(nodePath.join(env.shadowRoot, "doc.md"), "edited");

      await env.manager.encryptShadowChangesToOriginal();

      expect(fs.existsSync(nodePath.join(env.origRoot, "doc.md.enc.bak"))).toBe(false);
      expect(fs.existsSync(nodePath.join(env.origRoot, "doc.md.enc.new"))).toBe(false);
    } finally { env.cleanup(); }
  });

  it("verify-back: запись с симметричным decrypt-обратно должна совпасть с shadow", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "v.md", "old");
      await env.manager.decryptAllToShadow();
      fs.writeFileSync(nodePath.join(env.shadowRoot, "v.md"), "verified content");

      const result = await env.manager.encryptShadowChangesToOriginal();
      expect(result.failed).toHaveLength(0);

      // Decrypt оригинала и сравним посимвольно с shadow
      const encBuf = fs.readFileSync(nodePath.join(env.origRoot, "v.md.enc"));
      const decrypted = env.engine.decryptBuffer(encBuf).toString("utf8");
      const shadowContent = fs.readFileSync(nodePath.join(env.shadowRoot, "v.md"), "utf8");
      expect(decrypted).toBe(shadowContent);
    } finally { env.cleanup(); }
  });

  it("файл с одинаковым содержимым в shadow и оригинале: НЕ перешифровывается", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "same.md", "identical");
      await env.manager.decryptAllToShadow();
      // Не трогаем shadow — содержимое идентично

      const origEncStatBefore = fs.statSync(nodePath.join(env.origRoot, "same.md.enc"));
      await new Promise(r => setTimeout(r, 50));

      const result = await env.manager.encryptShadowChangesToOriginal();
      expect(result.encrypted).toHaveLength(0);

      const origEncStatAfter = fs.statSync(nodePath.join(env.origRoot, "same.md.enc"));
      // .enc не пересоздавался
      expect(origEncStatAfter.mtimeMs).toBe(origEncStatBefore.mtimeMs);
    } finally { env.cleanup(); }
  });

  it("игнорирует .obsidian как symlink (в shadow его нет в обычном смысле)", async () => {
    const env = await makeEnv();
    try {
      // .obsidian-симлинк не должен попасть в encrypt-back
      const origConfig = nodePath.join(env.origRoot, ".obsidian");
      fs.mkdirSync(origConfig);
      fs.writeFileSync(nodePath.join(origConfig, "settings.json"), "{}");

      await env.manager.setupObsidianSymlink();

      const result = await env.manager.encryptShadowChangesToOriginal();
      // Никаких .obsidian-файлов не должно попасть в encrypted/failed
      const all = [...result.encrypted, ...result.failed.map(f => f.path)];
      for (const p of all) {
        expect(p).not.toMatch(/^\.obsidian/);
      }
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// ФАЗА 4: миграция legacy → v2 (интеграция на реальной ФС)
// ─────────────────────────────────────────────

import * as nodeCrypto from "crypto";
import { detectFormat as detectFmt } from "../src/crypto/format";
import {
  LEGACY_SALT_DOMAIN,
  LEGACY_PBKDF2_ITERATIONS_NODE,
  LEGACY_PBKDF2_ITERATIONS_WEB,
} from "../src/crypto/constants";

const MIG_PASSWORD = "test-password"; // тот же, что в makeEnv

function legacyKeyMig(iters: number): Buffer {
  return nodeCrypto.pbkdf2Sync(
    MIG_PASSWORD, Buffer.from(LEGACY_SALT_DOMAIN, "utf8"), iters, 32, "sha512"
  );
}
function makeLegacyNodeBuf(plain: Buffer): Buffer {
  const iv = nodeCrypto.randomBytes(12);
  const c = nodeCrypto.createCipheriv("aes-256-gcm", legacyKeyMig(LEGACY_PBKDF2_ITERATIONS_NODE), iv);
  const enc = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]); // tag ПЕРЕД ciphertext
}
function makeLegacyWebBuf(plain: Buffer): Buffer {
  const iv = nodeCrypto.randomBytes(12);
  const c = nodeCrypto.createCipheriv("aes-256-gcm", legacyKeyMig(LEGACY_PBKDF2_ITERATIONS_WEB), iv);
  const enc = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, enc, c.getAuthTag()]); // tag В КОНЦЕ
}
async function writeRawEnc(env: TestEnv, relPath: string, buf: Buffer): Promise<void> {
  const encPath = nodePath.join(env.origRoot, ...relPath.split("/")) + ".enc";
  await fsp.mkdir(nodePath.dirname(encPath), { recursive: true });
  await fsp.writeFile(encPath, buf);
}
async function readEnc(env: TestEnv, relPath: string): Promise<Buffer> {
  return fsp.readFile(nodePath.join(env.origRoot, ...relPath.split("/")) + ".enc");
}

describe("ShadowVaultManager — миграция legacy → v2 (ФАЗА 4)", () => {
  it("hasLegacyFiles: true при legacy, false когда всё v2", async () => {
    const env = await makeEnv();
    try {
      expect(await env.manager.hasLegacyFiles()).toBe(false);
      await writeRawEnc(env, "old", makeLegacyNodeBuf(Buffer.from("hi")));
      expect(await env.manager.hasLegacyFiles()).toBe(true);
    } finally { env.cleanup(); }
  });

  it("мигрирует legacy-node и legacy-web в v2, plaintext сохраняется", async () => {
    const env = await makeEnv();
    try {
      await writeRawEnc(env, "node-note", makeLegacyNodeBuf(Buffer.from("узел node")));
      await writeRawEnc(env, "sub/web-note", makeLegacyWebBuf(Buffer.from("узел web")));

      const res = await env.manager.migrateLegacyToV2(MIG_PASSWORD);
      expect(res.migrated.sort()).toEqual(["node-note", "sub/web-note"]);
      expect(res.failed).toHaveLength(0);

      // Оба файла теперь v2 и расшифровываются новым ключом в исходный текст.
      const a = await readEnc(env, "node-note");
      const b = await readEnc(env, "sub/web-note");
      expect(detectFmt(new Uint8Array(a))).toBe("v2");
      expect(detectFmt(new Uint8Array(b))).toBe("v2");
      expect(env.engine.decryptBuffer(a).toString("utf8")).toBe("узел node");
      expect(env.engine.decryptBuffer(b).toString("utf8")).toBe("узел web");
    } finally { env.cleanup(); }
  });

  it("идемпотентность: повторный прогон пропускает v2, не портит данные", async () => {
    const env = await makeEnv();
    try {
      await writeRawEnc(env, "n", makeLegacyNodeBuf(Buffer.from("payload")));
      await env.manager.migrateLegacyToV2(MIG_PASSWORD);
      const afterFirst = await readEnc(env, "n");

      const res2 = await env.manager.migrateLegacyToV2(MIG_PASSWORD);
      expect(res2.migrated).toHaveLength(0);
      expect(res2.skipped).toBe(1);
      const afterSecond = await readEnc(env, "n");
      // Байты не изменились — v2 не перешифровывается заново.
      expect(afterSecond.equals(afterFirst)).toBe(true);
      expect(env.engine.decryptBuffer(afterSecond).toString("utf8")).toBe("payload");
    } finally { env.cleanup(); }
  });

  it("неверный пароль → файлы не тронуты, всё в failed", async () => {
    const env = await makeEnv();
    try {
      const orig = makeLegacyNodeBuf(Buffer.from("secret"));
      await writeRawEnc(env, "x", orig);

      const res = await env.manager.migrateLegacyToV2("WRONG-password");
      expect(res.migrated).toHaveLength(0);
      expect(res.failed).toHaveLength(1);

      // Оригинальный legacy .enc на диске не изменён.
      const after = await readEnc(env, "x");
      expect(after.equals(orig)).toBe(true);
      // .enc.new не остался на диске
      const newExists = fs.existsSync(nodePath.join(env.origRoot, "x.enc.new"));
      expect(newExists).toBe(false);
    } finally { env.cleanup(); }
  });

  it("частичный legacy: уже-v2 файлы пропускаются, legacy мигрируются", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "already-v2", "уже v2"); // пишет v2-форматом
      await writeRawEnc(env, "old", makeLegacyWebBuf(Buffer.from("старый")));

      const res = await env.manager.migrateLegacyToV2(MIG_PASSWORD);
      expect(res.migrated).toEqual(["old"]);
      expect(res.skipped).toBe(1);
      expect(env.engine.decryptBuffer(await readEnc(env, "already-v2")).toString("utf8")).toBe("уже v2");
      expect(env.engine.decryptBuffer(await readEnc(env, "old")).toString("utf8")).toBe("старый");
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// ФАЗА 5 — безопасный exportShadowToOriginal (disableEncryption)
// ─────────────────────────────────────────────
describe("ShadowVaultManager — exportShadowToOriginal (безопасный откат)", () => {
  it("успешный путь: plaintext появляется в оригинале, ВСЕ .enc удалены", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "alpha");
      await writeEncrypted(env, "sub/b.md", "beta");
      await env.manager.decryptAllToShadow();

      const res = await env.manager.exportShadowToOriginal();
      expect(res.failed).toHaveLength(0);
      expect(res.exported.sort()).toEqual(["a.md", "sub/b.md"]);

      // plaintext на месте
      expect(fs.readFileSync(nodePath.join(env.origRoot, "a.md"), "utf8")).toBe("alpha");
      expect(fs.readFileSync(nodePath.join(env.origRoot, "sub", "b.md"), "utf8")).toBe("beta");
      // .enc удалены батчем в конце
      expect(fs.existsSync(nodePath.join(env.origRoot, "a.md.enc"))).toBe(false);
      expect(fs.existsSync(nodePath.join(env.origRoot, "sub", "b.md.enc"))).toBe(false);
    } finally { env.cleanup(); }
  });

  it("сбой в середине: НИ ОДИН .enc не удалён, plaintext не потерян, понятная ошибка", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "ok.md", "good");
      await writeEncrypted(env, "boom.md", "explode");
      await env.manager.decryptAllToShadow();

      // Детерминированный сбой фазы 1 без mock'ов: делаем целевой plaintext-путь
      // boom.md КАТАЛОГОМ — atomicWrite (rename файла поверх каталога) упадёт,
      // boom.md попадёт в failed, .enc удалять нельзя.
      fs.mkdirSync(nodePath.join(env.origRoot, "boom.md"), { recursive: true });

      const res = await env.manager.exportShadowToOriginal();

      expect(res.failed.map(f => f.path)).toContain("boom.md");
      // КРИТИЧНО: оба .enc нетронуты (батч-удаление фазы 2 не выполнялось)
      expect(fs.existsSync(nodePath.join(env.origRoot, "ok.md.enc"))).toBe(true);
      expect(fs.existsSync(nodePath.join(env.origRoot, "boom.md.enc"))).toBe(true);
      // .enc по-прежнему расшифровывается в исходный plaintext (не потеряно)
      expect(env.engine.decryptBuffer(
        fs.readFileSync(nodePath.join(env.origRoot, "boom.md.enc"))
      ).toString("utf8")).toBe("explode");
    } finally { env.cleanup(); }
  });

  it("идемпотентность: повторный вызов после успеха безопасен", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "doc.md", "content");
      await env.manager.decryptAllToShadow();

      const r1 = await env.manager.exportShadowToOriginal();
      expect(r1.failed).toHaveLength(0);
      // Повторный вызов: plaintext уже есть, .enc уже нет — не падает
      const r2 = await env.manager.exportShadowToOriginal();
      expect(r2.failed).toHaveLength(0);
      expect(fs.readFileSync(nodePath.join(env.origRoot, "doc.md"), "utf8")).toBe("content");
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// ФАЗА 5 — sync encrypt-back при закрытии (потеря последней правки)
// ─────────────────────────────────────────────
describe("ShadowVaultManager — encryptUnsyncedChangesSync / hasUnsyncedChangesSync", () => {
  it("незавершённая правка дошифровывается до удаления shadow", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "v1");
      await env.manager.decryptAllToShadow();

      // Имитируем «последнюю правку» в shadow, которую write-through не успел
      // зашифровать (mtime shadow заведомо новее .enc).
      const enc = nodePath.join(env.origRoot, "note.md.enc");
      const past = new Date(Date.now() - 10_000);
      fs.utimesSync(enc, past, past);
      fs.writeFileSync(nodePath.join(env.shadowRoot, "note.md"), "v2-последняя правка");

      expect(env.manager.hasUnsyncedChangesSync()).toBe(true);

      const r = env.manager.encryptUnsyncedChangesSync();
      expect(r.failed).toHaveLength(0);
      expect(r.encrypted).toBeGreaterThanOrEqual(1);

      // .enc теперь содержит последнюю правку
      const plain = env.engine.decryptBuffer(fs.readFileSync(enc)).toString("utf8");
      expect(plain).toBe("v2-последняя правка");
    } finally { env.cleanup(); }
  });

  it("новый файл в shadow без .enc считается несхороненным и шифруется", async () => {
    const env = await makeEnv();
    try {
      fs.mkdirSync(env.shadowRoot, { recursive: true });
      fs.writeFileSync(nodePath.join(env.shadowRoot, "fresh.md"), "только в shadow");

      expect(env.manager.hasUnsyncedChangesSync()).toBe(true);
      const r = env.manager.encryptUnsyncedChangesSync();
      expect(r.encrypted).toBeGreaterThanOrEqual(1);

      const enc = nodePath.join(env.origRoot, "fresh.md.enc");
      expect(fs.existsSync(enc)).toBe(true);
      expect(env.engine.decryptBuffer(fs.readFileSync(enc)).toString("utf8")).toBe("только в shadow");
    } finally { env.cleanup(); }
  });

  it("после дошифровки несхороненных изменений не остаётся (shadow можно удалять)", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "x.md", "old");
      await env.manager.decryptAllToShadow();
      const enc = nodePath.join(env.origRoot, "x.md.enc");
      const past = new Date(Date.now() - 10_000);
      fs.utimesSync(enc, past, past);
      fs.writeFileSync(nodePath.join(env.shadowRoot, "x.md"), "edited");

      env.manager.encryptUnsyncedChangesSync();
      expect(env.manager.hasUnsyncedChangesSync()).toBe(false);
    } finally { env.cleanup(); }
  });

  it("идентичное содержимое (shadow не новее .enc) — не считается несхороненным", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "same.md", "stable");
      await env.manager.decryptAllToShadow();
      // shadow не трогаем; даём .enc более новый mtime чтобы исключить ложное срабатывание
      const enc = nodePath.join(env.origRoot, "same.md.enc");
      const future = new Date(Date.now() + 5_000);
      fs.utimesSync(enc, future, future);

      expect(env.manager.hasUnsyncedChangesSync()).toBe(false);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// ФАЗА 5 — pendingWrites / drainPending (дренаж при закрытии)
// ─────────────────────────────────────────────
describe("ShadowVaultManager — pendingWrites / drainPending", () => {
  it("trackPending регистрирует промис и снимает по завершении", async () => {
    const env = await makeEnv();
    try {
      let resolve!: () => void;
      const p = new Promise<void>((r) => { resolve = r; });
      env.manager.trackPending(p);
      expect(env.manager.pendingCount()).toBe(1);
      resolve();
      await p;
      // микрозадача finally
      await Promise.resolve();
      expect(env.manager.pendingCount()).toBe(0);
    } finally { env.cleanup(); }
  });

  it("drainPending дожидается всех in-flight операций", async () => {
    const env = await makeEnv();
    try {
      let done = false;
      const p = new Promise<void>((r) => setTimeout(() => { done = true; r(); }, 30));
      env.manager.trackPending(p);
      await env.manager.drainPending();
      expect(done).toBe(true);
      expect(env.manager.pendingCount()).toBe(0);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// reEncryptAll — смена ключа (пароль и/или email)
// ─────────────────────────────────────────────

describe("ShadowVaultManager — reEncryptAll (смена ключа)", () => {
  it("смена ПАРОЛЯ: файлы читаются новым ключом, старым — нет", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "alpha");
      await writeEncrypted(env, "sub/b.md", "beta");

      const newEngine = new CryptoEngine();
      await newEngine.deriveKey("test@test.local", "new-password");

      const calls: Array<[number, number]> = [];
      await env.manager.reEncryptAll(newEngine, (d, t) => calls.push([d, t]));

      // Новый ключ читает
      const encA = await fsp.readFile(nodePath.join(env.origRoot, "a.md.enc"));
      expect(newEngine.decryptBuffer(encA).toString("utf8")).toBe("alpha");
      const encB = await fsp.readFile(nodePath.join(env.origRoot, "sub", "b.md.enc"));
      expect(newEngine.decryptBuffer(encB).toString("utf8")).toBe("beta");

      // Старый ключ больше не читает
      expect(() => env.engine.decryptBuffer(encA)).toThrow();

      expect(calls.length).toBeGreaterThan(0);
      newEngine.destroy();
    } finally { env.cleanup(); }
  });

  it("смена EMAIL: новый ключ из нового email расшифровывает старые файлы", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "secret-email-change");

      // Новый email → новая соль → новый ключ (пароль не меняется).
      const newEngine = new CryptoEngine();
      await newEngine.deriveKey("changed@test.local", "test-password");

      await env.manager.reEncryptAll(newEngine, () => {});

      const enc = await fsp.readFile(nodePath.join(env.origRoot, "note.md.enc"));
      expect(newEngine.decryptBuffer(enc).toString("utf8")).toBe("secret-email-change");
      // Старый ключ (старый email) больше не подходит
      expect(() => env.engine.decryptBuffer(enc)).toThrow();
      newEngine.destroy();
    } finally { env.cleanup(); }
  });

  it("не оставляет .enc.new артефактов после успешной пере-шифровки", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "x.md", "data");
      const newEngine = new CryptoEngine();
      await newEngine.deriveKey("test@test.local", "another-pass");
      await env.manager.reEncryptAll(newEngine, () => {});
      expect(fs.existsSync(nodePath.join(env.origRoot, "x.md.enc.new"))).toBe(false);
      expect(fs.existsSync(nodePath.join(env.origRoot, "x.md.enc"))).toBe(true);
      newEngine.destroy();
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Регресс: каскад детекта legacy / самовосстановление блоба / пустые .enc
// ─────────────────────────────────────────────

import * as nodeCrypto from "crypto";
import {
  LEGACY_SALT_DOMAIN,
  LEGACY_PBKDF2_ITERATIONS_NODE,
} from "../src/crypto/constants";
import { detectFormat } from "../src/crypto/format";

/** Пишет 0-байтный .enc (старый артефакт пустого файла) в originalRoot. */
async function writeEmptyEnc(env: TestEnv, relPath: string): Promise<void> {
  const encPath = nodePath.join(env.origRoot, ...relPath.split("/")) + ".enc";
  await fsp.mkdir(nodePath.dirname(encPath), { recursive: true });
  await fsp.writeFile(encPath, Buffer.alloc(0));
}

/** Пишет настоящий legacy-node .enc ([IV][tag][ct], 310000 итераций). */
async function writeLegacyEnc(env: TestEnv, relPath: string): Promise<void> {
  const key = nodeCrypto.pbkdf2Sync(
    "test-password",
    Buffer.from(LEGACY_SALT_DOMAIN, "utf8"),
    LEGACY_PBKDF2_ITERATIONS_NODE,
    32,
    "sha512"
  );
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from("legacy data")), cipher.final()]);
  const tag = cipher.getAuthTag();
  const buf = Buffer.concat([iv, tag, enc]); // legacy-node layout
  const encPath = nodePath.join(env.origRoot, ...relPath.split("/")) + ".enc";
  await fsp.mkdir(nodePath.dirname(encPath), { recursive: true });
  await fsp.writeFile(encPath, buf);
}

describe("hasLegacyFiles — позитивный детект legacy (не !== v2)", () => {
  it("v2-файлы + один пустой (0 байт) .enc → НЕ legacy (false)", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "v2 content");
      await writeEmptyEnc(env, "empty.md");
      expect(await env.manager.hasLegacyFiles()).toBe(false);
    } finally { env.cleanup(); }
  });

  it("только v2-файлы → НЕ legacy", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "x");
      await writeEncrypted(env, "b/c.md", "y");
      expect(await env.manager.hasLegacyFiles()).toBe(false);
    } finally { env.cleanup(); }
  });

  it("настоящий legacy-файл → legacy (true)", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "v2");
      await writeLegacyEnc(env, "old.md");
      expect(await env.manager.hasLegacyFiles()).toBe(true);
    } finally { env.cleanup(); }
  });
});

describe("validateV2Password — самовосстановление блоба при v2 + blob=null", () => {
  it("верный пароль (тот же движок) → true", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "secret");
      await writeEmptyEnc(env, "empty.md"); // пустые игнорируются
      expect(await env.manager.validateV2Password()).toBe(true);
    } finally { env.cleanup(); }
  });

  it("неверный пароль (другой движок) → false, файлы целы", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "secret");
      const before = await fsp.readFile(nodePath.join(env.origRoot, "a.md.enc"));

      // Менеджер с НЕВЕРНЫМ ключом над теми же .enc.
      const wrongEngine = new CryptoEngine();
      await wrongEngine.deriveKey("test@test.local", "WRONG-password");
      const wrongMgr = new ShadowVaultManager(wrongEngine, env.origRoot, env.shadowRoot + "-w");
      await wrongMgr.initialize();

      expect(await wrongMgr.validateV2Password()).toBe(false);
      // .enc не тронут
      const after = await fsp.readFile(nodePath.join(env.origRoot, "a.md.enc"));
      expect(after.equals(before)).toBe(true);
      wrongEngine.destroy();
    } finally { env.cleanup(); }
  });

  it("нет валидных v2-файлов (только пустые) → null", async () => {
    const env = await makeEnv();
    try {
      await writeEmptyEnc(env, "empty.md");
      expect(await env.manager.validateV2Password()).toBeNull();
    } finally { env.cleanup(); }
  });
});

describe("Пустой plaintext → валидный v2-контейнер (не 0 байт)", () => {
  it("encryptOne для пустого файла даёт v2-контейнер, round-trip в пустоту", async () => {
    const env = await makeEnv();
    try {
      const shadowAbs = env.manager.shadowAbs("empty.md");
      await fsp.mkdir(nodePath.dirname(shadowAbs), { recursive: true });
      await fsp.writeFile(shadowAbs, Buffer.alloc(0));
      await env.manager.encryptOne("empty.md");

      const encBuf = await fsp.readFile(nodePath.join(env.origRoot, "empty.md.enc"));
      expect(encBuf.length).toBeGreaterThan(0);
      expect(detectFormat(new Uint8Array(encBuf))).toBe("v2");
      const back = env.engine.decryptBuffer(encBuf);
      expect(back.length).toBe(0);
    } finally { env.cleanup(); }
  });
});
