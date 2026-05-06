/**
 * Юнит-тесты QueueManager.
 *
 * Стратегия: вместо реальных файлов используем управляемые decryptFn.
 * "Управляемый промис" (ControlledDecrypt) позволяет вручную решать когда
 * расшифровка файла завершится — это делает тесты порядка и конкурентности
 * детерминированными без sleep().
 */

import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import { QueueManager, QueueProgress } from "../src/queue-manager";

// ─────────────────────────────────────────────
// Утилиты
// ─────────────────────────────────────────────

/** Немедленная decryptFn — резолвится синхронно */
function makeInstantDecrypt(): (path: string) => Promise<void> {
  return jest.fn(async (_path: string) => { /* мгновенно */ });
}

/** Управляемая decryptFn: позволяет вручную завершать расшифровку конкретного файла */
function makeControlledDecrypt() {
  const resolvers = new Map<string, () => void>();
  const calls: string[] = [];
  let autoResolve = false; // если true — fn завершается мгновенно для новых вызовов

  const fn = jest.fn(async (path: string) => {
    calls.push(path);
    if (autoResolve) return; // режим мгновенного завершения
    await new Promise<void>((resolve) => {
      resolvers.set(path, resolve);
    });
  });

  return {
    fn,
    /** Завершает расшифровку конкретного файла */
    resolve: (path: string) => {
      const r = resolvers.get(path);
      if (r) { r(); resolvers.delete(path); }
    },
    /**
     * Включает autoResolve и завершает все уже ожидающие вызовы.
     * Важно: будущие вызовы fn() после resolveAll() тоже завершатся мгновенно —
     * это нужно когда воркер берёт новый файл УЖЕ ПОСЛЕ нашего вызова resolveAll().
     */
    resolveAll: () => {
      autoResolve = true;
      for (const [, r] of resolvers) r();
      resolvers.clear();
    },
    /** Список путей, для которых decryptFn была вызвана (в порядке вызова) */
    calls,
  };
}

/** Собирает снапшоты прогресса в массив */
function collectProgress(queue: QueueManager): QueueProgress[] {
  const snapshots: QueueProgress[] = [];
  queue.onProgress((p) => snapshots.push({ ...p }));
  return snapshots;
}

// ─────────────────────────────────────────────
// enqueue() / prioritize()
// ─────────────────────────────────────────────

describe("QueueManager — enqueue()", () => {
  it("добавляет пути в очередь", () => {
    const q = new QueueManager(makeInstantDecrypt());
    q.enqueue(["a.md", "b.md", "c.md"]);
    expect(q.getProgress().total).toBe(3);
    expect(q.getProgress().pending).toBe(3);
  });

  it("не добавляет дубликаты", () => {
    const q = new QueueManager(makeInstantDecrypt());
    q.enqueue(["a.md", "b.md"]);
    q.enqueue(["b.md", "c.md"]); // b.md — дубль
    expect(q.getProgress().total).toBe(3);
  });

  it("пустой enqueue не меняет состояние", () => {
    const q = new QueueManager(makeInstantDecrypt());
    q.enqueue([]);
    expect(q.getProgress().total).toBe(0);
  });

  it("isComplete=false при непустой очереди", () => {
    const q = new QueueManager(makeInstantDecrypt());
    q.enqueue(["a.md"]);
    expect(q.getProgress().isComplete).toBe(false);
  });
});

describe("QueueManager — prioritize()", () => {
  it("перемещает файл в начало очереди", async () => {
    const ctrl = makeControlledDecrypt();
    // concurrency=1: только один воркер — гарантирует строгий порядок
    const q = new QueueManager(ctrl.fn, { concurrency: 1 });
    q.enqueue(["a.md", "b.md", "c.md", "d.md"]);

    // Запускаем, но не await — воркер ждёт на a.md
    const startPromise = q.start();

    // a.md сейчас в inProgress. Приоритизируем d.md
    // (ждём один тик чтобы воркер успел взять a.md)
    await Promise.resolve();
    q.prioritize("d.md");

    // Завершаем все файлы по одному
    ctrl.resolve("a.md");
    await Promise.resolve(); await Promise.resolve();
    ctrl.resolve("d.md"); // должен идти вторым
    await Promise.resolve(); await Promise.resolve();
    ctrl.resolve("b.md");
    await Promise.resolve(); await Promise.resolve();
    ctrl.resolve("c.md");
    await startPromise;

    expect(ctrl.calls[0]).toBe("a.md");
    expect(ctrl.calls[1]).toBe("d.md"); // приоритет сработал
  });

  it("не делает ничего если файл уже расшифрован", async () => {
    const q = new QueueManager(makeInstantDecrypt(), { concurrency: 1 });
    q.enqueue(["a.md"]);
    await q.start();

    // a.md теперь completed
    expect(q.isDecrypted("a.md")).toBe(true);
    // prioritize не должен сломать состояние
    q.prioritize("a.md");
    expect(q.getProgress().total).toBe(1);
  });

  it("lazy add: добавляет файл которого нет в очереди", async () => {
    const ctrl = makeControlledDecrypt();
    const q = new QueueManager(ctrl.fn, { concurrency: 1 });
    q.enqueue(["a.md"]);

    const startPromise = q.start();
    await Promise.resolve();

    // ghost.md не был в очереди — добавится lazy
    q.prioritize("ghost.md");
    expect(q.getProgress().total).toBe(2);

    ctrl.resolveAll();
    await startPromise;

    expect(q.isDecrypted("ghost.md")).toBe(true);
  });

  it("не перемещает файл уже в inProgress", async () => {
    const ctrl = makeControlledDecrypt();
    const q = new QueueManager(ctrl.fn, { concurrency: 1 });
    q.enqueue(["a.md", "b.md"]);

    const startPromise = q.start();
    await Promise.resolve(); // a.md взят в работу

    expect(q.isInProgress("a.md")).toBe(true);
    q.prioritize("a.md"); // no-op: уже обрабатывается

    ctrl.resolveAll();
    await startPromise;

    // a.md должен быть только один раз в calls
    expect(ctrl.calls.filter(p => p === "a.md")).toHaveLength(1);
  });
});

// ─────────────────────────────────────────────
// start() / stop() / прогресс
// ─────────────────────────────────────────────

describe("QueueManager — start() и прогресс", () => {
  it("обрабатывает все файлы и isComplete=true после завершения", async () => {
    const q = new QueueManager(makeInstantDecrypt());
    q.enqueue(["a.md", "b.md", "c.md"]);
    await q.start();

    const p = q.getProgress();
    expect(p.completed).toBe(3);
    expect(p.pending).toBe(0);
    expect(p.isComplete).toBe(true);
    expect(p.percentage).toBe(100);
  });

  it("emitProgress вызывается при каждом завершённом файле", async () => {
    const q = new QueueManager(makeInstantDecrypt(), { concurrency: 1 });
    q.enqueue(["a.md", "b.md", "c.md"]);

    const snapshots = collectProgress(q);
    await q.start();

    // Минимум 3 события прогресса (по одному на файл)
    expect(snapshots.length).toBeGreaterThanOrEqual(3);
    // Последнее событие — 100%
    expect(snapshots[snapshots.length - 1].percentage).toBe(100);
  });

  it("onComplete вызывается ровно один раз", async () => {
    const q = new QueueManager(makeInstantDecrypt());
    q.enqueue(["a.md", "b.md"]);

    let completeCount = 0;
    q.onComplete(() => completeCount++);
    await q.start();

    expect(completeCount).toBe(1);
  });

  it("percentage растёт по мере обработки (concurrency=1)", async () => {
    const ctrl = makeControlledDecrypt();
    const q = new QueueManager(ctrl.fn, { concurrency: 1 });
    q.enqueue(["a.md", "b.md", "c.md", "d.md"]);

    const percentages: number[] = [];
    q.onProgress((p) => percentages.push(p.percentage));

    const startPromise = q.start();
    await Promise.resolve();
    ctrl.resolve("a.md"); await Promise.resolve(); await Promise.resolve();
    ctrl.resolve("b.md"); await Promise.resolve(); await Promise.resolve();
    ctrl.resolve("c.md"); await Promise.resolve(); await Promise.resolve();
    ctrl.resolve("d.md");
    await startPromise;

    // Прогресс должен только расти
    for (let i = 1; i < percentages.length; i++) {
      expect(percentages[i]).toBeGreaterThanOrEqual(percentages[i - 1]);
    }
    expect(percentages[percentages.length - 1]).toBe(100);
  });

  it("stop() прерывает обработку", async () => {
    const ctrl = makeControlledDecrypt();
    const q = new QueueManager(ctrl.fn, { concurrency: 1 });
    q.enqueue(["a.md", "b.md", "c.md"]);

    const startPromise = q.start();
    await Promise.resolve(); // a.md в работе

    q.stop(); // сигнал остановки

    ctrl.resolve("a.md"); // завершаем текущий
    await startPromise;

    // После a.md воркер видит running=false и останавливается
    expect(q.getProgress().completed).toBeLessThan(3);
    expect(q.getProgress().isComplete).toBe(false);
  });
});

// ─────────────────────────────────────────────
// Конкурентность
// ─────────────────────────────────────────────

describe("QueueManager — concurrency", () => {
  it("не превышает лимит конкурентных воркеров", async () => {
    let maxConcurrent = 0;
    let current = 0;

    const decryptFn = async (_path: string) => {
      current++;
      maxConcurrent = Math.max(maxConcurrent, current);
      // Небольшая задержка чтобы конкурентные вызовы перекрылись по времени
      await new Promise<void>((r) => setTimeout(r, 5));
      current--;
    };

    const CONCURRENCY = 2;
    const q = new QueueManager(decryptFn, { concurrency: CONCURRENCY });
    q.enqueue(["a.md", "b.md", "c.md", "d.md", "e.md", "f.md"]);
    await q.start();

    expect(maxConcurrent).toBeLessThanOrEqual(CONCURRENCY);
    expect(q.getProgress().completed).toBe(6);
  });

  it("concurrency=1 обрабатывает файлы строго по одному", async () => {
    let concurrent = 0;
    let violation = false;

    const decryptFn = async (_path: string) => {
      concurrent++;
      if (concurrent > 1) violation = true;
      await new Promise<void>((r) => setTimeout(r, 2));
      concurrent--;
    };

    const q = new QueueManager(decryptFn, { concurrency: 1 });
    q.enqueue(["a.md", "b.md", "c.md", "d.md"]);
    await q.start();

    expect(violation).toBe(false);
  });
});

// ─────────────────────────────────────────────
// Обработка ошибок
// ─────────────────────────────────────────────

describe("QueueManager — обработка ошибок", () => {
  it("ошибка одного файла не останавливает обработку остальных", async () => {
    const decryptFn = async (path: string) => {
      if (path === "bad.md") throw new Error("Файл повреждён");
    };

    const q = new QueueManager(decryptFn, { concurrency: 1 });
    q.enqueue(["good1.md", "bad.md", "good2.md"]);
    await q.start();

    const p = q.getProgress();
    expect(p.completed).toBe(2); // good1 и good2
    expect(p.failed).toBe(1);    // bad.md
    expect(p.isComplete).toBe(true); // очередь пуста
  });

  it("failed файлы не попадают в completed", async () => {
    const decryptFn = async (path: string) => {
      if (path === "fail.md") throw new Error("fail");
    };

    const q = new QueueManager(decryptFn, { concurrency: 1 });
    q.enqueue(["fail.md"]);
    await q.start();

    expect(q.isDecrypted("fail.md")).toBe(false);
    expect(q.getProgress().failed).toBe(1);
  });

  it("failed файл не вызывает дублирование в прогрессе", async () => {
    const decryptFn = async (path: string) => {
      throw new Error("all fail");
    };

    const q = new QueueManager(decryptFn);
    q.enqueue(["a.md", "b.md"]);
    await q.start();

    const p = q.getProgress();
    expect(p.failed).toBe(2);
    expect(p.completed).toBe(0);
    expect(p.total).toBe(2);
    // Сумма completed+failed+pending+inProgress = total
    expect(p.completed + p.failed + p.pending + p.inProgress).toBe(p.total);
  });
});

// ─────────────────────────────────────────────
// Подписки и отписки
// ─────────────────────────────────────────────

describe("QueueManager — onProgress / onComplete отписка", () => {
  it("отписка от onProgress прекращает получение событий", async () => {
    const q = new QueueManager(makeInstantDecrypt(), { concurrency: 1 });
    q.enqueue(["a.md", "b.md", "c.md"]);

    let count = 0;
    const unsub = q.onProgress(() => count++);

    // Обрабатываем один файл, потом отписываемся
    const ctrl = makeControlledDecrypt();
    const q2 = new QueueManager(ctrl.fn, { concurrency: 1 });
    q2.enqueue(["x.md", "y.md"]);

    let count2 = 0;
    const unsub2 = q2.onProgress(() => count2++);

    const p = q2.start();
    await Promise.resolve();
    ctrl.resolve("x.md");
    await Promise.resolve(); await Promise.resolve();

    unsub2(); // отписываемся после первого файла

    ctrl.resolve("y.md");
    await p;

    // Должен быть только 1 прогресс-событие (для x.md), y.md уже после отписки
    expect(count2).toBe(1);
  });

  it("onComplete не срабатывает после stop()", async () => {
    const ctrl = makeControlledDecrypt();
    const q = new QueueManager(ctrl.fn, { concurrency: 1 });
    q.enqueue(["a.md", "b.md"]);

    let completed = false;
    q.onComplete(() => completed = true);

    const p = q.start();
    await Promise.resolve();
    q.stop();
    ctrl.resolve("a.md");
    await p;

    expect(completed).toBe(false); // stop() → не все обработаны → нет complete
  });
});

// ─────────────────────────────────────────────
// getProgress() инварианты
// ─────────────────────────────────────────────

describe("QueueManager — инварианты getProgress()", () => {
  it("completed + failed + pending + inProgress = total в любой момент", async () => {
    const ctrl = makeControlledDecrypt();
    const q = new QueueManager(ctrl.fn, { concurrency: 2 });
    q.enqueue(["a.md", "b.md", "c.md", "d.md"]);

    const violations: string[] = [];
    q.onProgress((p) => {
      const sum = p.completed + p.failed + p.pending + p.inProgress;
      if (sum !== p.total) violations.push(`${sum} !== ${p.total}`);
    });

    const startPromise = q.start();
    await Promise.resolve(); await Promise.resolve();
    ctrl.resolveAll();
    await startPromise;

    expect(violations).toHaveLength(0);
  });

  it("пустая очередь: percentage=100, isComplete=false (нет задач)", () => {
    const q = new QueueManager(makeInstantDecrypt());
    const p = q.getProgress();
    // Без enqueue total=0, isComplete=false (нет смысла говорить что «готово»)
    expect(p.percentage).toBe(100);
    expect(p.isComplete).toBe(false);
  });
});
