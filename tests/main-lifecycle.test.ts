/**
 * Тесты жизненного цикла плагина (гонка shutdown ↔ vault-события):
 *
 *   1. liveShadowManager — гейт: возвращает null при shadowManager==null /
 *      shuttingDown / !sessionActive; и менеджер, когда сессия жива.
 *   2. handleCreate/handleDelete/handleRename НЕ бросают при shadowManager==null
 *      (раньше был TypeError: Cannot read properties of null).
 *   3. reportError — дедупликация: две идентичные ошибки подряд → один файл-репорт
 *      (устранение лавины одинаковых баг-репортов при закрытии Obsidian).
 *
 * Плагин инстанцируется через Object.create(prototype) — обходим тяжёлый
 * конструктор Obsidian Plugin; задаём только поля, которых касаются методы.
 */

import { describe, it, expect, beforeEach } from "@jest/globals";
import ShadowVaultPlugin from "../src/main";
import { DiagnosticsController } from "../src/diagnostics-controller";

/** Заглушка логгера — методы no-op, чтобы методы плагина не падали. */
function fakeLogger() {
  return {
    debug() {},
    info() {},
    warn() {},
    error() {},
    tail() {
      return [] as string[];
    },
  };
}

/**
 * Минимальный «полу-инициализированный» экземпляр плагина для unit-тестов
 * приватных методов. Без вызова конструктора Obsidian.Plugin.
 */
function makePlugin(): any {
  const p: any = Object.create(ShadowVaultPlugin.prototype);
  p.logger = fakeLogger();
  // Поля, которые читает дедупликация reportError.
  p.recentReports = new Map<string, number>();
  return p;
}

describe("liveShadowManager (гейт жизненного цикла)", () => {
  it("возвращает null когда shadowManager == null", () => {
    const p = makePlugin();
    p.shadowManager = null;
    p.sessionActive = true;
    p.shuttingDown = false;
    expect(p.liveShadowManager("test")).toBeNull();
  });

  it("возвращает null когда идёт shutdown (shuttingDown=true)", () => {
    const p = makePlugin();
    p.shadowManager = {}; // как будто ещё не обнулён
    p.sessionActive = false;
    p.shuttingDown = true;
    expect(p.liveShadowManager("test")).toBeNull();
  });

  it("возвращает null когда сессия не активна", () => {
    const p = makePlugin();
    p.shadowManager = {};
    p.sessionActive = false;
    p.shuttingDown = false;
    expect(p.liveShadowManager("test")).toBeNull();
  });

  it("возвращает менеджер когда сессия жива", () => {
    const p = makePlugin();
    const sm = { id: "live" };
    p.shadowManager = sm;
    p.sessionActive = true;
    p.shuttingDown = false;
    expect(p.liveShadowManager("test")).toBe(sm);
  });
});

describe("vault-обработчики при shadowManager == null НЕ бросают", () => {
  const fakeFile = { path: "note.md" } as any;

  beforeEach(() => {});

  it("handleCreate безопасно игнорирует событие", async () => {
    const p = makePlugin();
    p.shadowManager = null;
    p.sessionActive = false;
    p.shuttingDown = true;
    await expect(p.handleCreate(fakeFile)).resolves.toBeUndefined();
  });

  it("handleDelete безопасно игнорирует событие", async () => {
    const p = makePlugin();
    p.shadowManager = null;
    p.sessionActive = false;
    p.shuttingDown = true;
    await expect(p.handleDelete(fakeFile)).resolves.toBeUndefined();
  });

  it("handleRename безопасно игнорирует событие", async () => {
    const p = makePlugin();
    p.shadowManager = null;
    p.sessionActive = false;
    p.shuttingDown = true;
    await expect(p.handleRename(fakeFile, "old.md")).resolves.toBeUndefined();
  });
});

describe("reportError — дедупликация баг-репортов (делегирование в DiagnosticsController)", () => {
  // Дедуп-логика переехала в DiagnosticsController; plugin.reportError — тонкая
  // обёртка. Тест проверяет публичный API plugin.reportError end-to-end с
  // инжектированным контроллером (счётчик фактических записей репорта).
  function makeReportingPlugin() {
    const p = makePlugin();
    p.sessionActive = false;
    p.shuttingDown = false;
    // Считаем фактические записи репортов.
    p.reportCalls = 0;
    const bugReporter = {
      report: async () => {
        p.reportCalls++;
        return `/fake/bugreport-${p.reportCalls}.json`;
      },
    };
    p.bugReporter = bugReporter;
    // collectVaultStats не нужен реальный — заглушаем.
    p.collectVaultStats = async () => ({});
    p.diagnostics = new DiagnosticsController({
      logger: p.logger,
      bugReporter: bugReporter as any,
      collectStats: async () => ({}),
      showNotice: () => {},
    });
    return p;
  }

  it("две идентичные ошибки подряд → ровно один файл-репорт", async () => {
    const p = makeReportingPlugin();
    const err = new Error("Cannot read properties of null (reading 'trackPending')");
    const path1 = await p.reportError("write.modify", err, undefined, { silent: true });
    const path2 = await p.reportError("write.modify", err, undefined, { silent: true });
    expect(path1).not.toBeNull();
    expect(path2).toBeNull(); // подавлено дедупликацией
    expect(p.reportCalls).toBe(1);
  });

  it("разные операции репортятся независимо", async () => {
    const p = makeReportingPlugin();
    const err = new Error("boom");
    await p.reportError("write.modify", err, undefined, { silent: true });
    await p.reportError("write.create", err, undefined, { silent: true });
    expect(p.reportCalls).toBe(2);
  });

  it("после истечения окна дедупликации тот же тип репортится снова", async () => {
    const p = makeReportingPlugin();
    const err = new Error("boom");
    await p.reportError("write.modify", err, undefined, { silent: true });
    // Сдвигаем ts последней записи в прошлое за пределы окна дедупа (приватная
    // карта recentReports контроллера).
    const recent: Map<string, number> = (p.diagnostics as any).recentReports;
    for (const [sig] of recent) {
      recent.set(sig, Date.now() - 60_000);
    }
    const path2 = await p.reportError("write.modify", err, undefined, { silent: true });
    expect(path2).not.toBeNull();
    expect(p.reportCalls).toBe(2);
  });
});
