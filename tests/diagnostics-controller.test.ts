/**
 * Тесты DiagnosticsController: сигнатура ошибки (стабильность/различимость),
 * дедупликация баг-репортов в окне REPORT_DEDUP_MS и ОТСУТСТВИЕ секретов в
 * логе и баг-репорте. Поведение должно совпадать с прежним god-object main.ts.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from "@jest/globals";
import { DiagnosticsController } from "../src/diagnostics-controller";
import { Logger, LogLevel, LogAdapter } from "../src/logger";
import { BugReporter, BugReportEnv } from "../src/bug-report";

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

interface Harness {
  ctrl: DiagnosticsController;
  adapter: MemAdapter;
  notices: Array<{ message: string; timeout: number }>;
  reportFiles: () => string[];
}

function makeHarness(): Harness {
  const adapter = new MemAdapter();
  const logger = new Logger(adapter, {
    logDir: "plugins/shadow-vault/logs",
    minLevel: LogLevel.DEBUG,
    ringSize: 100,
    maxFileBytes: 64 * 1024,
    maxFiles: 1,
    flushIntervalMs: 1500,
    mirrorConsole: false,
  });
  const bugReporter = new BugReporter(adapter, REPORT_DIR, ENV, () => logger.tail(50));
  const notices: Array<{ message: string; timeout: number }> = [];
  const ctrl = new DiagnosticsController({
    logger,
    bugReporter,
    collectStats: async () => undefined,
    showNotice: (message, timeout) => { notices.push({ message, timeout }); },
  });
  const reportFiles = () =>
    [...adapter.files.keys()].filter((k) => k.startsWith(REPORT_DIR + "/"));
  return { ctrl, adapter, notices, reportFiles };
}

describe("DiagnosticsController.errorSignature", () => {
  let ctrl: DiagnosticsController;
  beforeEach(() => { ctrl = makeHarness().ctrl; });

  it("одинаковые ошибки одной операции дают одну сигнатуру", () => {
    const e = new Error("boom");
    const a = ctrl.errorSignature("unlock.desktop", e);
    const b = ctrl.errorSignature("unlock.desktop", e);
    expect(a).toBe(b);
  });

  it("разные операции дают разные сигнатуры для той же ошибки", () => {
    const e = new Error("boom");
    const a = ctrl.errorSignature("unlock.desktop", e);
    const b = ctrl.errorSignature("unlock.mobile", e);
    expect(a).not.toBe(b);
  });

  it("сигнатура имеет формат operation|name|head", () => {
    const e = new TypeError("kaboom");
    e.stack = "TypeError: kaboom\n    at foo (file.ts:1:1)";
    const sig = ctrl.errorSignature("op.x", e);
    expect(sig.startsWith("op.x|TypeError|")).toBe(true);
    expect(sig.split("|").length).toBeGreaterThanOrEqual(3);
  });

  it("разные типы ошибок различимы по name", () => {
    const a = ctrl.errorSignature("op", new TypeError("x"));
    const b = ctrl.errorSignature("op", new RangeError("x"));
    expect(a).not.toBe(b);
  });
});

describe("DiagnosticsController.reportError дедупликация", () => {
  let h: Harness;
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(0);
    h = makeHarness();
  });
  afterEach(() => {
    jest.useRealTimers();
  });

  function fixedError(): Error {
    const e = new Error("identical failure");
    e.stack = "Error: identical failure\n    at same (place.ts:10:5)";
    return e;
  }

  it("идентичная ошибка в окне создаёт только один баг-репорт", async () => {
    const p1 = await h.ctrl.reportError("op.dup", fixedError());
    expect(p1).not.toBeNull();
    expect(h.reportFiles().length).toBe(1);

    jest.setSystemTime(5_000); // в пределах окна 10с
    const p2 = await h.ctrl.reportError("op.dup", fixedError());
    expect(p2).toBeNull();
    expect(h.reportFiles().length).toBe(1);
  });

  it("после окна REPORT_DEDUP_MS та же ошибка репортится снова", async () => {
    await h.ctrl.reportError("op.dup", fixedError());
    expect(h.reportFiles().length).toBe(1);

    jest.setSystemTime(10_001); // за пределами окна
    const p2 = await h.ctrl.reportError("op.dup", fixedError());
    expect(p2).not.toBeNull();
    expect(h.reportFiles().length).toBe(2);
  });

  it("разные ошибки дедуплицируются независимо", async () => {
    await h.ctrl.reportError("op.a", fixedError());
    const e2 = new Error("other failure");
    e2.stack = "Error: other failure\n    at elsewhere (other.ts:1:1)";
    const p2 = await h.ctrl.reportError("op.b", e2);
    expect(p2).not.toBeNull();
    expect(h.reportFiles().length).toBe(2);
  });

  it("silent не показывает Notice, но репорт пишется", async () => {
    await h.ctrl.reportError("op.silent", fixedError(), undefined, { silent: true });
    expect(h.notices.length).toBe(0);
    expect(h.reportFiles().length).toBe(1);
  });

  it("не-silent показывает Notice с путём к репорту", async () => {
    const p = await h.ctrl.reportError("op.notice", fixedError());
    expect(h.notices.length).toBe(1);
    expect(h.notices[0].message).toContain(p as string);
  });
});

describe("DiagnosticsController — отсутствие секретов", () => {
  it("секреты из context маскируются в баг-репорте и не утекают", async () => {
    const h = makeHarness();
    const secret = "SUPER_SECRET_PASSWORD_12345";
    const e = new Error("auth failed");
    await h.ctrl.reportError("unlock.desktop", e, {
      password: secret,
      pin: "9999",
      masterKey: "deadbeef",
      path: "vault/note.md",
    });

    const reportPath = h.reportFiles()[0];
    const raw = h.adapter.files.get(reportPath) ?? "";
    expect(raw.length).toBeGreaterThan(0);
    expect(raw).not.toContain(secret);
    expect(raw).not.toContain("9999");
    expect(raw).not.toContain("deadbeef");
    // Безопасное поле (путь) допустимо в репорте.
    expect(raw).toContain("vault/note.md");
  });

  it("в логах нет содержимого секретных полей сообщения", async () => {
    const h = makeHarness();
    const e = new Error("boom");
    await h.ctrl.reportError("op.x", e, { token: "T0P_SECRET" });
    // logTail попадает в репорт — убеждаемся что секрет не просочился в лог.
    const reportPath = h.reportFiles()[0];
    const raw = h.adapter.files.get(reportPath) ?? "";
    expect(raw).not.toContain("T0P_SECRET");
  });
});
