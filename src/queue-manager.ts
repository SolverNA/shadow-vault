/**
 * QueueManager — менеджер фоновой расшифровки файлов хранилища.
 *
 * Работает независимо от Obsidian API — принимает колбэк decryptFn
 * и список путей для расшифровки. Это делает класс полностью тестируемым.
 *
 * Алгоритм:
 *   1. enqueue(paths) — заполняет очередь нерасшифрованными файлами.
 *   2. start() — запускает N воркеров (concurrency), каждый берёт файл
 *      из начала очереди, вызывает decryptFn, репортит прогресс.
 *   3. prioritize(path) — перемещает файл в начало очереди [0].
 *      Если файл уже обрабатывается — ничего не делаем (скоро будет готов).
 *      Если файла нет в очереди — добавляем в начало (lazy add).
 *   4. По завершению всех элементов — вызываются onComplete-коллбэки.
 *
 * Гарантии:
 *   - Файл не будет обрабатываться дважды одновременно.
 *   - Ошибки расшифровки отдельного файла не останавливают всю очередь.
 *   - stop() прерывает обработку после завершения текущих воркеров.
 */

/** Тип функции расшифровки, передаётся извне (обычно ShadowVaultManager.ensureDecrypted) */
export type DecryptFn = (normalizedPath: string) => Promise<void>;

export interface QueueProgress {
  total:      number;   // всего файлов в задаче
  completed:  number;   // успешно расшифровано
  failed:     number;   // ошибки расшифровки
  pending:    number;   // ещё не взято в работу
  inProgress: number;   // прямо сейчас обрабатывается
  percentage: number;   // 0–100, без учёта inProgress
  isComplete: boolean;  // true когда pending + inProgress = 0
}

export type ProgressCallback = (progress: QueueProgress) => void;
export type CompleteCallback  = () => void;

export interface QueueManagerOptions {
  /** Количество параллельных воркеров расшифровки (default: 3) */
  concurrency?: number;
}

export class QueueManager {
  private readonly decryptFn: DecryptFn;
  private readonly concurrency: number;

  /** Очередь: первый элемент — наивысший приоритет */
  private pending: string[] = [];
  /** Файлы, которые сейчас обрабатываются воркерами */
  private inProgressSet = new Set<string>();
  /** Успешно расшифрованные файлы */
  private completedSet  = new Set<string>();
  /** Файлы, при расшифровке которых произошла ошибка */
  private failedMap     = new Map<string, Error>();

  /** Общее количество файлов, зафиксированное при enqueue */
  private total = 0;
  /** Флаг — воркеры должны продолжать работу */
  private running = false;

  private progressCallbacks = new Set<ProgressCallback>();
  private completeCallbacks = new Set<CompleteCallback>();

  constructor(decryptFn: DecryptFn, options: QueueManagerOptions = {}) {
    this.decryptFn  = decryptFn;
    this.concurrency = options.concurrency ?? 3;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Управление очередью
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Добавляет пути в очередь (в конец, FIFO).
   * Дубликаты и уже обработанные файлы пропускаются.
   * Должен вызываться до start().
   */
  enqueue(paths: string[]): void {
    const known = new Set([
      ...this.pending,
      ...this.inProgressSet,
      ...this.completedSet,
      ...this.failedMap.keys(),
    ]);

    for (const p of paths) {
      if (!known.has(p)) {
        this.pending.push(p);
        known.add(p);
      }
    }
    this.recalcTotal();
    this.emitProgress();
  }

  /**
   * Перемещает файл в начало очереди — «срочная» расшифровка.
   *
   * Вызывается хуком file-open: пользователь кликнул на заметку,
   * которой ещё нет в Теневом хранилище. Воркер возьмёт её первой
   * на следующей итерации.
   *
   * Если файл уже в inProgress или completed — ничего не делаем.
   * Если файла нет в очереди совсем — добавляем в начало (lazy add).
   */
  prioritize(normalizedPath: string): void {
    if (this.completedSet.has(normalizedPath))  return; // уже готов
    if (this.inProgressSet.has(normalizedPath)) return; // уже обрабатывается

    const idx = this.pending.indexOf(normalizedPath);
    if (idx === 0) return; // уже первый

    if (idx > 0) {
      // Есть в очереди — переносим на начало
      this.pending.splice(idx, 1);
      this.pending.unshift(normalizedPath);
    } else {
      // Нет в очереди вообще — добавляем в начало
      this.pending.unshift(normalizedPath);
      this.recalcTotal();
    }
    // Не эмитируем progress здесь: приоритет — не завершение работы
  }

  /** Возвращает true если файл уже расшифрован (есть в shadow cache) */
  isDecrypted(normalizedPath: string): boolean {
    return this.completedSet.has(normalizedPath);
  }

  /** Возвращает true если файл сейчас обрабатывается воркером */
  isInProgress(normalizedPath: string): boolean {
    return this.inProgressSet.has(normalizedPath);
  }

  /** Снапшот текущего прогресса */
  getProgress(): QueueProgress {
    const done = this.completedSet.size + this.failedMap.size;
    return {
      total:      this.total,
      completed:  this.completedSet.size,
      failed:     this.failedMap.size,
      pending:    this.pending.length,
      inProgress: this.inProgressSet.size,
      percentage: this.total > 0
        ? Math.round((done / this.total) * 100)
        : 100,
      isComplete: this.total > 0
        ? this.pending.length === 0 && this.inProgressSet.size === 0
        : false,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Запуск и остановка
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Запускает N воркеров-расшифровщиков.
   * Возвращает Promise, который разрешается когда все воркеры завершились.
   *
   * Для фонового запуска: не await'ить, сохранить Promise для graceful shutdown.
   * Для последовательной обработки (тесты): await queue.start().
   */
  async start(): Promise<void> {
    if (this.running) return; // повторный вызов — no-op
    this.running = true;

    const workers = Array.from(
      { length: this.concurrency },
      () => this.runWorker()
    );
    await Promise.allSettled(workers);

    this.running = false;

    // Эмитируем завершение только если всё было обработано (не принудительная остановка)
    if (this.pending.length === 0 && this.inProgressSet.size === 0) {
      this.emitProgress();
      this.emitComplete();
    }
  }

  /**
   * Сигнализирует воркерам остановиться после завершения текущей задачи.
   * Не ждёт фактической остановки — воркеры завершатся самостоятельно.
   */
  stop(): void {
    this.running = false;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Подписки на события
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Подписывается на обновления прогресса.
   * @returns Функция отписки
   */
  onProgress(cb: ProgressCallback): () => void {
    this.progressCallbacks.add(cb);
    return () => this.progressCallbacks.delete(cb);
  }

  /**
   * Подписывается на событие завершения всей очереди.
   * @returns Функция отписки
   */
  onComplete(cb: CompleteCallback): () => void {
    this.completeCallbacks.add(cb);
    return () => this.completeCallbacks.delete(cb);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Приватные методы
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Тело одного воркера: в цикле берёт задачу из очереди, расшифровывает, отчитывается.
   * Завершается когда очередь пуста или выставлен флаг running=false.
   */
  private async runWorker(): Promise<void> {
    while (this.running) {
      const path = this.dequeue();
      if (path === null) break; // очередь пуста — воркер больше не нужен

      try {
        await this.decryptFn(path);
        this.inProgressSet.delete(path);
        this.completedSet.add(path);
      } catch (err) {
        // Ошибка одного файла не останавливает очередь
        this.inProgressSet.delete(path);
        this.failedMap.set(path, err instanceof Error ? err : new Error(String(err)));
        console.warn(`[QueueManager] Не удалось расшифровать "${path}":`, err);
      }

      this.emitProgress();
    }
  }

  /**
   * Атомарно извлекает первый элемент из pending и перемещает в inProgress.
   * Возвращает null если очередь пуста.
   */
  private dequeue(): string | null {
    if (this.pending.length === 0) return null;
    const path = this.pending.shift()!;
    this.inProgressSet.add(path);
    return path;
  }

  /** Пересчитывает total — вызывается при изменении состава очереди */
  private recalcTotal(): void {
    this.total =
      this.completedSet.size +
      this.failedMap.size +
      this.inProgressSet.size +
      this.pending.length;
  }

  private emitProgress(): void {
    const p = this.getProgress();
    for (const cb of this.progressCallbacks) {
      try { cb(p); } catch { /* колбэк не должен ломать очередь */ }
    }
  }

  private emitComplete(): void {
    for (const cb of this.completeCallbacks) {
      try { cb(); } catch { /* аналогично */ }
    }
  }
}
