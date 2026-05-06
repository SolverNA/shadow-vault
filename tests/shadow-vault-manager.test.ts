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
  await engine.deriveKey("test-password");

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
    await engine.deriveKey("pwd");
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
      // Размер должен быть 5 (без 28 байт заголовка IV+AuthTag)
      expect(stat!.size).toBe(5);
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
