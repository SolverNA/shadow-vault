/**
 * DiagnosticsController — централизованная обработка ошибок ключевых операций
 * и дедупликация баг-репортов.
 *
 * Вынесен из god-object main.ts (поведение сохранено ТОЧНО):
 *   • логирует error в Logger;
 *   • пишет баг-репорт через BugReporter, но не чаще одного на сигнатуру
 *     в пределах окна REPORT_DEDUP_MS (дедупликация лавины одинаковых ошибок);
 *   • показывает пользователю Notice с путём к репорту (через колбэк showNotice,
 *     чтобы не тянуть зависимость от obsidian в контроллер).
 *
 * Узкий контекст (НЕ весь Plugin): логгер, баг-репортер, колбэк сбора статистик
 * хранилища и колбэк показа уведомления. Жизненный цикл (создание Logger/
 * BugReporter, регистрация window error/unhandledrejection) остаётся в main.
 */

import { Logger } from "./logger";
import { BugReporter, VaultStats } from "./bug-report";

/** Опции одного вызова reportError. */
export interface ReportErrorOptions {
  /** Не показывать Notice (для фоновых/глобальных ошибок). */
  silent?: boolean;
}

/** Зависимости контроллера — узкий контекст вместо всего Plugin. */
export interface DiagnosticsDeps {
  logger: Logger;
  bugReporter: BugReporter;
  /** Сбор безопасных статистик хранилища (только числа, без содержимого). */
  collectStats: () => Promise<VaultStats | undefined>;
  /** Показ уведомления пользователю (main передаёт обёртку над Notice). */
  showNotice: (message: string, timeoutMs: number) => void;
}

export class DiagnosticsController {
  private readonly logger: Logger;
  private readonly bugReporter: BugReporter;
  private readonly collectStats: () => Promise<VaultStats | undefined>;
  private readonly showNotice: (message: string, timeoutMs: number) => void;

  /**
   * Дедупликация баг-репортов: сигнатура ошибки → ts последнего репорта.
   * Идентичная ошибка (operation + name + первая строка stack/message) в
   * пределах окна REPORT_DEDUP_MS НЕ создаёт новый файл-репорт. Устраняет
   * лавину одинаковых баг-репортов (напр. при закрытии Obsidian одно и то же
   * событие срабатывало 9 раз → 9 идентичных файлов). Первая ошибка каждого
   * типа репортится всегда.
   */
  private readonly recentReports = new Map<string, number>();
  private static readonly REPORT_DEDUP_MS = 10_000;

  constructor(deps: DiagnosticsDeps) {
    this.logger = deps.logger;
    this.bugReporter = deps.bugReporter;
    this.collectStats = deps.collectStats;
    this.showNotice = deps.showNotice;
  }

  /**
   * Централизованный обработчик ошибок ключевых операций: (а) логирует error,
   * (б) пишет баг-репорт в каталог плагина, (в) показывает пользователю Notice
   * с путём к репорту. Не глотает данные и не роняет приложение молча.
   *
   * @returns путь к сохранённому баг-репорту (или null).
   */
  async reportError(
    operation: string,
    error: unknown,
    context?: Record<string, unknown>,
    opts?: ReportErrorOptions,
  ): Promise<string | null> {
    const msg = error instanceof Error ? error.message : String(error);
    this.logger?.error("error", `ошибка в операции «${operation}»: ${msg}`, {
      operation,
      ...(context ?? {}),
    });

    // Дедупликация: идентичная ошибка в окне REPORT_DEDUP_MS не плодит файлы.
    // Логируем всегда (см. выше), но баг-репорт пишем не чаще одного на сигнатуру.
    const signature = this.errorSignature(operation, error);
    const now = Date.now();
    const last = this.recentReports.get(signature);
    if (last !== undefined && now - last < DiagnosticsController.REPORT_DEDUP_MS) {
      this.logger?.debug("error", "баг-репорт подавлен дедупликацией", {
        operation,
        sinceMs: now - last,
      });
      return null;
    }
    this.recentReports.set(signature, now);
    this.pruneRecentReports(now);

    let path: string | null = null;
    try {
      const stats = await this.collectStats().catch(() => undefined);
      path = await this.bugReporter.report({ operation, error, context, stats });
    } catch (e) {
      console.error("[ShadowVault] reportError: не удалось создать баг-репорт:", e);
    }
    if (!opts?.silent) {
      if (path) {
        this.showNotice(`⚠️ Произошла ошибка, создан баг-репорт:\n${path}`, 10000);
      } else {
        this.showNotice("⚠️ Произошла ошибка (баг-репорт сохранить не удалось).", 8000);
      }
    }
    return path;
  }

  /**
   * Сигнатура ошибки для дедупликации: operation + name + первая значимая
   * строка stack (или message). Намеренно грубая — идентичные по сути ошибки
   * (одно и то же место кода) дают одну сигнатуру независимо от ts/произвольных
   * чисел в сообщении.
   */
  errorSignature(operation: string, error: unknown): string {
    let name = "Error";
    let head = "";
    if (error instanceof Error) {
      name = error.name || "Error";
      const firstStackLine = (error.stack ?? "")
        .split("\n")
        .map((l) => l.trim())
        .find((l) => l.startsWith("at "));
      head = firstStackLine ?? error.message ?? "";
    } else {
      head = String(error);
    }
    return `${operation}|${name}|${head}`;
  }

  /** Удаляет из карты дедупликации записи старше окна — не даём ей расти. */
  private pruneRecentReports(now: number): void {
    for (const [sig, ts] of this.recentReports) {
      if (now - ts >= DiagnosticsController.REPORT_DEDUP_MS) {
        this.recentReports.delete(sig);
      }
    }
  }
}
