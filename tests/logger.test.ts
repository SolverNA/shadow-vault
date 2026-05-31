/**
 * Тесты логгера: уровни, ротация по размеру, маскирование секретов,
 * ring buffer / tail. Запись идёт через in-memory LogAdapter (mobile-safe,
 * тот же интерфейс, что у Obsidian DataAdapter) — node:fs не используется.
 */

import { describe, it, expect, beforeEach } from "@jest/globals";
import {
  Logger,
  LogLevel,
  LogAdapter,
  redactFields,
  isSensitiveKey,
  formatEntry,
} from "../src/logger";

/** In-memory adapter, совместимый с Obsidian DataAdapter (подмножество). */
class MemAdapter implements LogAdapter {
  files = new Map<string, string>();

  async write(path: string, data: string): Promise<void> {
    this.files.set(path, data);
  }
  async append(path: string, data: string): Promise<void> {
    this.files.set(path, (this.files.get(path) ?? "") + data);
  }
  async exists(path: string): Promise<boolean> {
    return this.files.has(path);
  }
  async mkdir(_path: string): Promise<void> {
    /* директории как множество префиксов — в тесте не нужны */
  }
  async list(path: string): Promise<{ files: string[]; folders: string[] }> {
    const prefix = path.endsWith("/") ? path : path + "/";
    const files = [...this.files.keys()].filter((k) => k.startsWith(prefix));
    return { files, folders: [] };
  }
  async remove(path: string): Promise<void> {
    this.files.delete(path);
  }
  async read(path: string): Promise<string> {
    return this.files.get(path) ?? "";
  }
  async stat(path: string): Promise<{ size: number; mtime: number } | null> {
    const v = this.files.get(path);
    if (v === undefined) return null;
    return { size: v.length, mtime: 0 };
  }
}

function makeLogger(adapter: MemAdapter, overrides = {}): Logger {
  return new Logger(adapter, {
    logDir: "plugins/shadow-vault/logs",
    minLevel: LogLevel.DEBUG,
    flushIntervalMs: 999999, // вручную флашим в тестах
    mirrorConsole: false,
    ...overrides,
  });
}

describe("Logger — уровни", () => {
  let adapter: MemAdapter;

  beforeEach(() => {
    adapter = new MemAdapter();
  });

  it("пишет записи >= minLevel и игнорирует ниже", async () => {
    const log = makeLogger(adapter, { minLevel: LogLevel.INFO });
    log.debug("t", "debug-msg");
    log.info("t", "info-msg");
    log.warn("t", "warn-msg");
    await log.flush();

    const content = adapter.files.get(log.logFile) ?? "";
    expect(content).not.toContain("debug-msg");
    expect(content).toContain("info-msg");
    expect(content).toContain("warn-msg");
  });

  it("setMinLevel переключает уровень на лету", async () => {
    const log = makeLogger(adapter, { minLevel: LogLevel.DEBUG });
    log.debug("t", "first-debug");
    log.setMinLevel(LogLevel.WARN);
    log.debug("t", "second-debug");
    log.error("t", "an-error");
    await log.flush();
    const content = adapter.files.get(log.logFile) ?? "";
    expect(content).toContain("first-debug");
    expect(content).not.toContain("second-debug");
    expect(content).toContain("an-error");
  });

  it("формат записи содержит ISO-timestamp, уровень и tag", () => {
    const line = formatEntry({
      ts: "2026-05-31T00:00:00.000Z",
      level: LogLevel.WARN,
      tag: "auth",
      message: "hi",
    });
    expect(line).toContain("2026-05-31T00:00:00.000Z");
    expect(line).toContain("[WARN]");
    expect(line).toContain("[auth]");
    expect(line).toContain("hi");
  });
});

describe("Logger — ring buffer / tail", () => {
  it("tail возвращает последние N записей", () => {
    const log = makeLogger(new MemAdapter(), { ringSize: 100 });
    for (let i = 0; i < 50; i++) log.info("t", `msg-${i}`);
    const tail = log.tail(5);
    expect(tail).toHaveLength(5);
    expect(tail[4]).toContain("msg-49");
    expect(tail[0]).toContain("msg-45");
  });

  it("ring buffer ограничен по размеру", () => {
    const log = makeLogger(new MemAdapter(), { ringSize: 10 });
    for (let i = 0; i < 100; i++) log.info("t", `m-${i}`);
    expect(log.snapshot()).toHaveLength(10);
    expect(log.snapshot()[9].message).toBe("m-99");
  });
});

describe("Logger — ротация по размеру", () => {
  it("превышение лимита создаёт log.1.txt и начинает новый log.txt", async () => {
    const adapter = new MemAdapter();
    const log = makeLogger(adapter, { maxFileBytes: 200, maxFiles: 3 });

    // Пишем порции, флашим между ними — несколько превысят лимит.
    for (let i = 0; i < 20; i++) {
      log.info("t", `entry number ${i} padding-padding-padding`);
      await log.flush();
    }

    const dir = "plugins/shadow-vault/logs";
    // Должен появиться хотя бы один ротированный файл.
    expect(adapter.files.has(`${dir}/log.1.txt`)).toBe(true);
    // Активный файл существует и не превышает лимит чрезмерно.
    const active = adapter.files.get(`${dir}/log.txt`) ?? "";
    expect(active.length).toBeLessThanOrEqual(200 + 200);
    // Число файлов лога не превышает maxFiles.
    const logFiles = await log.listLogFiles();
    expect(logFiles.length).toBeLessThanOrEqual(3);
  });
});

describe("Logger — маскирование секретов", () => {
  it("isSensitiveKey ловит password/pin/key/blob/plaintext", () => {
    for (const k of ["password", "userPassword", "pin", "masterKey", "rawKey", "verificationBlob", "plaintext", "deviceSalt", "token"]) {
      expect(isSensitiveKey(k)).toBe(true);
    }
    for (const k of ["path", "size", "count", "ms", "status"]) {
      expect(isSensitiveKey(k)).toBe(false);
    }
  });

  it("redactFields маскирует значения чувствительных ключей рекурсивно", () => {
    const out = redactFields({
      password: "hunter2",
      pin: "1234",
      masterKey: "deadbeef",
      path: "notes/secret-plan.md",
      nested: { apiKey: "abc", size: 10 },
    });
    expect(out!.password).toBe("[REDACTED]");
    expect(out!.pin).toBe("[REDACTED]");
    expect(out!.masterKey).toBe("[REDACTED]");
    expect(out!.path).toBe("notes/secret-plan.md");
    expect((out!.nested as Record<string, unknown>).apiKey).toBe("[REDACTED]");
    expect((out!.nested as Record<string, unknown>).size).toBe(10);
  });

  it("бинарные значения не попадают в лог как содержимое", () => {
    const out = redactFields({ data: new Uint8Array([1, 2, 3, 4]) });
    expect(String(out!.data)).toMatch(/\[binary 4B\]/);
  });

  it("в файле лога нет секретов, даже если их подали в fields", async () => {
    const adapter = new MemAdapter();
    const log = makeLogger(adapter);
    log.info("auth", "вход", {
      password: "hunter2",
      pin: "9999",
      masterKey: "ABCDEF",
      path: "ok/path.md",
    });
    await log.flush();
    const content = adapter.files.get(log.logFile) ?? "";
    expect(content).not.toContain("hunter2");
    expect(content).not.toContain("9999");
    expect(content).not.toContain("ABCDEF");
    expect(content).toContain("[REDACTED]");
    expect(content).toContain("ok/path.md");
  });
});

describe("Logger — clear", () => {
  it("удаляет все файлы логов", async () => {
    const adapter = new MemAdapter();
    const log = makeLogger(adapter);
    log.info("t", "hello");
    await log.flush();
    expect((await log.listLogFiles()).length).toBeGreaterThan(0);
    await log.clear();
    expect(await log.listLogFiles()).toHaveLength(0);
    expect(log.snapshot()).toHaveLength(0);
  });
});
