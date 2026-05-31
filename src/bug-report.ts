/**
 * BugReporter — обязательный баг-репорт при любой пойманной ошибке в ключевых
 * операциях плагина ShadowVault.
 *
 * Поведение:
 *   - При ошибке генерируется структурированный JSON-репорт и СОХРАНЯЕТСЯ в
 *     каталог плагина (рядом с логами): bug-reports/bugreport-<ts>.json.
 *   - Репорт включает: timestamp, версию плагина, платформу, ОС/арх (desktop —
 *     лениво через os; mobile — Platform-флаги), версию Obsidian, операцию/контекст,
 *     тип ошибки + message + stack, «хвост» лога, безопасные статистики.
 *   - Пользователю показывается Notice с путём к репорту.
 *
 * ⚠️ БЕЗОПАСНОСТЬ: репорт НЕ содержит секретов и plaintext. Контекст-поля
 * проходят через redactFields(). Содержимое файлов хранилища НЕ включается —
 * только числовые статистики (кол-во файлов, .enc, суммарный размер).
 *
 * КРОСС-ПЛАТФОРМЕННОСТЬ: запись через тот же LogAdapter (Obsidian adapter),
 * без top-level node:fs. ОС/арх на desktop берутся лениво за гейтом isNodeRuntime.
 */

import { LogAdapter, redactFields } from "./logger";

/** Безопасные статистики хранилища (только числа, без содержимого). */
export interface VaultStats {
  totalFiles?: number;
  encFiles?: number;
  totalBytes?: number;
  formatVersion?: number;
  [extra: string]: number | undefined;
}

export interface BugReportInput {
  /** Операция/контекст, где произошла ошибка (напр. "unlock.desktop"). */
  operation: string;
  /** Сама ошибка. */
  error: unknown;
  /** Дополнительные безопасные поля контекста (проходят редактирование). */
  context?: Record<string, unknown>;
  /** Безопасные статистики хранилища. */
  stats?: VaultStats;
}

export interface BugReportEnv {
  pluginVersion: string;
  /** "desktop" | "mobile". */
  platform: string;
  obsidianVersion?: string;
  isDesktop: boolean;
}

/** Готовая структура репорта (сериализуется в JSON). */
export interface BugReport {
  schema: number;
  timestamp: string;
  pluginVersion: string;
  platform: string;
  obsidianVersion?: string;
  os?: { type?: string; release?: string; arch?: string };
  operation: string;
  error: { name: string; message: string; stack?: string };
  context?: Record<string, unknown>;
  stats?: VaultStats;
  logTail: string[];
}

const SCHEMA = 1;

/** Нормализует произвольное брошенное значение в {name,message,stack}. */
export function normalizeError(err: unknown): {
  name: string;
  message: string;
  stack?: string;
} {
  if (err instanceof Error) {
    return {
      name: err.name || "Error",
      message: err.message || String(err),
      stack: err.stack,
    };
  }
  if (typeof err === "string") return { name: "Error", message: err };
  try {
    return { name: "NonError", message: JSON.stringify(err) };
  } catch {
    return { name: "NonError", message: String(err) };
  }
}

/** Лениво и безопасно собирает ОС/арх (desktop). На mobile вернёт undefined. */
function collectOsInfo(isDesktop: boolean): BugReport["os"] | undefined {
  if (!isDesktop) return undefined;
  try {
    // Ленивый импорт за гейтом — node:os недостижим на mobile.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { nos } = require("./node-fs") as typeof import("./node-fs");
    const os = nos();
    return { type: os.type(), release: os.release(), arch: os.arch() };
  } catch {
    return undefined;
  }
}

export class BugReporter {
  constructor(
    private readonly adapter: LogAdapter,
    private readonly reportDir: string,
    private readonly env: BugReportEnv,
    private readonly logTail: () => string[],
  ) {}

  get dir(): string {
    return this.reportDir;
  }

  /** Строит структуру репорта (без записи на диск). */
  build(input: BugReportInput): BugReport {
    return {
      schema: SCHEMA,
      timestamp: new Date().toISOString(),
      pluginVersion: this.env.pluginVersion,
      platform: this.env.platform,
      obsidianVersion: this.env.obsidianVersion,
      os: collectOsInfo(this.env.isDesktop),
      operation: input.operation,
      error: normalizeError(input.error),
      // Контекст проходит редактирование секретов на всякий случай.
      context: redactFields(input.context),
      stats: input.stats,
      logTail: this.logTail(),
    };
  }

  /**
   * Генерирует и сохраняет баг-репорт. Возвращает путь к файлу (или null,
   * если запись не удалась — но репорт не должен ронять основную операцию).
   */
  async report(input: BugReportInput): Promise<string | null> {
    const report = this.build(input);
    const ts = report.timestamp.replace(/[:.]/g, "-");
    // Короткий суффикс — чтобы два репорта в одну мс не перезаписали друг друга.
    const suffix = Math.random().toString(36).slice(2, 7);
    const path = `${this.reportDir}/bugreport-${ts}-${suffix}.json`;
    try {
      if (!(await this.adapter.exists(this.reportDir))) {
        await this.adapter.mkdir(this.reportDir);
      }
      await this.adapter.write(path, JSON.stringify(report, null, 2));
      return path;
    } catch (err) {
      console.error("[ShadowVault] BugReporter.report failed:", err);
      return null;
    }
  }

  /** Список сохранённых баг-репортов (имена файлов), новейшие первыми. */
  async list(): Promise<string[]> {
    try {
      const { files } = await this.adapter.list(this.reportDir);
      return files
        .filter((f) => /bugreport-.*\.json$/.test(f))
        .sort()
        .reverse();
    } catch {
      return [];
    }
  }

  /** Читает один репорт. */
  async read(path: string): Promise<string> {
    return this.adapter.read(path);
  }

  /** Удаляет все баг-репорты. */
  async clear(): Promise<void> {
    const files = await this.list();
    for (const f of files) {
      try {
        await this.adapter.remove(f);
      } catch {
        /* ignore */
      }
    }
  }
}
