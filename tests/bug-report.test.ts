/**
 * Тесты баг-репортера: генерация при ошибке, наличие ожидаемых полей,
 * ОТСУТСТВИЕ секретов/plaintext, сохранение через adapter (mobile-safe).
 */

import { describe, it, expect, beforeEach } from "@jest/globals";
import { BugReporter, BugReportEnv, normalizeError } from "../src/bug-report";
import { LogAdapter } from "../src/logger";

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
  async mkdir(_path: string): Promise<void> {}
  async list(path: string): Promise<{ files: string[]; folders: string[] }> {
    const prefix = path.endsWith("/") ? path : path + "/";
    return { files: [...this.files.keys()].filter((k) => k.startsWith(prefix)), folders: [] };
  }
  async remove(path: string): Promise<void> {
    this.files.delete(path);
  }
  async read(path: string): Promise<string> {
    return this.files.get(path) ?? "";
  }
}

const ENV: BugReportEnv = {
  pluginVersion: "2.0.0",
  platform: "mobile",
  isDesktop: false,
  obsidianVersion: "1.5.0",
};

const REPORT_DIR = "plugins/shadow-vault/bug-reports";

function makeReporter(adapter: MemAdapter, tail: string[] = ["log line A", "log line B"]): BugReporter {
  return new BugReporter(adapter, REPORT_DIR, ENV, () => tail);
}

describe("normalizeError", () => {
  it("извлекает name/message/stack из Error", () => {
    const e = new TypeError("boom");
    const n = normalizeError(e);
    expect(n.name).toBe("TypeError");
    expect(n.message).toBe("boom");
    expect(typeof n.stack).toBe("string");
  });
  it("обрабатывает строку и не-Error", () => {
    expect(normalizeError("oops").message).toBe("oops");
    expect(normalizeError({ a: 1 }).message).toContain("a");
  });
});

describe("BugReporter — генерация и поля", () => {
  let adapter: MemAdapter;
  beforeEach(() => {
    adapter = new MemAdapter();
  });

  it("сохраняет репорт при ошибке и возвращает путь", async () => {
    const reporter = makeReporter(adapter);
    const path = await reporter.report({
      operation: "unlock.mobile",
      error: new Error("decrypt failed"),
    });
    expect(path).toBeTruthy();
    expect(path!.startsWith(REPORT_DIR)).toBe(true);
    expect(adapter.files.has(path!)).toBe(true);
  });

  it("репорт содержит ожидаемые поля", async () => {
    const reporter = makeReporter(adapter);
    const report = reporter.build({
      operation: "migration.legacy",
      error: new Error("bad format"),
      stats: { totalFiles: 12, encFiles: 10, totalBytes: 4096, formatVersion: 2 },
    });
    expect(report.schema).toBe(1);
    expect(report.pluginVersion).toBe("2.0.0");
    expect(report.platform).toBe("mobile");
    expect(report.obsidianVersion).toBe("1.5.0");
    expect(report.operation).toBe("migration.legacy");
    expect(report.error.name).toBe("Error");
    expect(report.error.message).toBe("bad format");
    expect(report.stats!.encFiles).toBe(10);
    expect(report.logTail).toEqual(["log line A", "log line B"]);
    expect(typeof report.timestamp).toBe("string");
  });

  it("на mobile os-инфо отсутствует (нет node:os)", () => {
    const report = makeReporter(adapter).build({ operation: "x", error: new Error("e") });
    expect(report.os).toBeUndefined();
  });
});

describe("BugReporter — отсутствие секретов", () => {
  it("context с секретами редактируется, plaintext не утекает", async () => {
    const adapter = new MemAdapter();
    const reporter = makeReporter(adapter);
    const path = await reporter.report({
      operation: "unlock.mobile",
      error: new Error("fail"),
      context: {
        password: "hunter2",
        pin: "4321",
        masterKey: "DEADBEEF",
        plaintext: "my secret note body",
        path: "notes/ok.md",
      },
    });
    const raw = adapter.files.get(path!)!;
    expect(raw).not.toContain("hunter2");
    expect(raw).not.toContain("4321");
    expect(raw).not.toContain("DEADBEEF");
    expect(raw).not.toContain("my secret note body");
    expect(raw).toContain("[REDACTED]");
    // безопасные данные сохраняются
    expect(raw).toContain("notes/ok.md");
  });
});

describe("BugReporter — list / clear", () => {
  it("перечисляет и очищает репорты", async () => {
    const adapter = new MemAdapter();
    const reporter = makeReporter(adapter);
    await reporter.report({ operation: "a", error: new Error("1") });
    await reporter.report({ operation: "b", error: new Error("2") });
    const list = await reporter.list();
    expect(list.length).toBe(2);
    await reporter.clear();
    expect(await reporter.list()).toHaveLength(0);
  });
});
