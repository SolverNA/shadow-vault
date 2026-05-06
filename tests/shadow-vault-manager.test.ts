/**
 * Интеграционные тесты для ShadowVaultManager.
 *
 * Стратегия: реальные файловые операции в temp-директориях.
 * MockAdapter оборачивает fs-операции над originalRoot — симулирует
 * "что делал бы Obsidian без нашего патча".
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
// MockAdapter — симуляция оригинального адаптера Obsidian
// Работает с реальными файлами в originalRoot через fs.promises.
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
// Утилиты для тестов
// ─────────────────────────────────────────────

/** Записывает зашифрованный файл в originalRoot напрямую (симулирует уже зашифрованные файлы) */
async function writeEncrypted(env: TestEnv, relPath: string, plaintext: string): Promise<void> {
  const absPath = nodePath.join(env.origRoot, ...relPath.split("/"));
  await fsp.mkdir(nodePath.dirname(absPath), { recursive: true });
  const encrypted = env.engine.encryptBuffer(Buffer.from(plaintext, "utf8"));
  await fsp.writeFile(absPath, encrypted);
}

// ─────────────────────────────────────────────
// Тесты инициализации и путей
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
// Тесты операций чтения
// ─────────────────────────────────────────────

describe("ShadowVaultManager — read()", () => {
  it("читает уже зашифрованный файл: расшифровывает и возвращает plaintext", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "# Hello\n\nSecret content.");
      const result = await env.adapter.read("note.md");
      expect(result).toBe("# Hello\n\nSecret content.");
    } finally { env.cleanup(); }
  });

  it("повторное read() берёт данные из shadow-кэша без повторной расшифровки", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "cached content");
      await env.adapter.read("note.md");

      // Удаляем зашифрованный оригинал — если повторный read() не лезет туда, тест пройдёт
      await fsp.unlink(nodePath.join(env.origRoot, "note.md"));
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
// Тесты операций записи
// ─────────────────────────────────────────────

describe("ShadowVaultManager — write()", () => {
  it("write() создаёт файл в shadow И зашифрованный файл в original", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("new-note.md", "Hello, vault!");

      // Теневое хранилище: plaintext
      const shadowContent = await fsp.readFile(
        nodePath.join(env.shadowRoot, "new-note.md"), "utf8"
      );
      expect(shadowContent).toBe("Hello, vault!");

      // Оригинальное хранилище: зашифрованный блоб
      const encBuf = await fsp.readFile(nodePath.join(env.origRoot, "new-note.md"));
      expect(encBuf.length).toBeGreaterThan(28); // заголовок 28 байт + данные
    } finally { env.cleanup(); }
  });

  it("зашифрованный файл в original можно расшифровать обратно", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("secret.md", "Top secret");

      const encBuf = await fsp.readFile(nodePath.join(env.origRoot, "secret.md"));
      const decBuf = env.engine.decryptBuffer(encBuf);
      expect(decBuf.toString("utf8")).toBe("Top secret");
    } finally { env.cleanup(); }
  });

  it("write() создаёт промежуточные директории", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("Projects/Alpha/notes.md", "project notes");

      expect(fs.existsSync(nodePath.join(env.shadowRoot, "Projects", "Alpha", "notes.md"))).toBe(true);
      expect(fs.existsSync(nodePath.join(env.origRoot,   "Projects", "Alpha", "notes.md"))).toBe(true);
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

      const encBuf = await fsp.readFile(nodePath.join(env.origRoot, "note.md"));
      const dec = env.engine.decryptBuffer(encBuf);
      expect(dec.toString("utf8")).toBe("version 2");
    } finally { env.cleanup(); }
  });

  it("атомарность: нет .shadowtmp файла после успешной записи", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("atomic.md", "data");
      const tmpPath = nodePath.join(env.origRoot, "atomic.md.shadowtmp");
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
  it("exists() возвращает true для зашифрованного файла", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "note.md", "content");
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
      // Размер должен быть 5 (без 28 байт заголовка)
      expect(stat!.size).toBe(5);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты list()
// ─────────────────────────────────────────────

describe("ShadowVaultManager — list()", () => {
  it("list() возвращает файлы из original хранилища", async () => {
    const env = await makeEnv();
    try {
      await writeEncrypted(env, "a.md", "A");
      await writeEncrypted(env, "b.md", "B");
      fs.mkdirSync(nodePath.join(env.origRoot, "Notes"));

      const result = await env.adapter.list("");
      expect(result.files).toContain("a.md");
      expect(result.files).toContain("b.md");
      expect(result.folders).toContain("Notes");
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

  it("remove() удаляет из обоих хранилищ", async () => {
    const env = await makeEnv();
    try {
      await env.adapter.write("to-delete.md", "bye");
      await env.adapter.remove("to-delete.md");

      expect(fs.existsSync(nodePath.join(env.origRoot, "to-delete.md"))).toBe(false);
      expect(fs.existsSync(nodePath.join(env.shadowRoot, "to-delete.md"))).toBe(false);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Тесты bypass (.obsidian)
// ─────────────────────────────────────────────

describe("ShadowVaultManager — bypass для .obsidian", () => {
  it("write() к .obsidian пишет незашифрованный файл в original", async () => {
    const env = await makeEnv();
    try {
      fs.mkdirSync(nodePath.join(env.origRoot, ".obsidian"), { recursive: true });
      await env.adapter.write(".obsidian/app.json", '{"theme":"dark"}');

      // Файл должен быть в оригинальном хранилище как есть (незашифрован)
      const content = fs.readFileSync(
        nodePath.join(env.origRoot, ".obsidian", "app.json"), "utf8"
      );
      expect(content).toBe('{"theme":"dark"}');

      // В теневом хранилища не должен появиться
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
  it("после unpatch() адаптер возвращается к оригинальному поведению", async () => {
    const env = await makeEnv();
    try {
      // Записываем через патченый адаптер — создаст зашифрованный файл в original
      await env.adapter.write("note.md", "secret");

      // Снимаем патч
      env.manager.unpatch(env.adapter);

      // Теперь read() читает raw-байты напрямую из original (зашифрованный блоб)
      // — это НЕ будет "secret"
      const rawContent = await env.adapter.read("note.md");
      expect(rawContent).not.toBe("secret"); // сырые байты шифртекста
    } finally { env.cleanup(); }
  });
});
