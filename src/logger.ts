/**
 * Logger — кросс-платформенное debug-логирование плагина ShadowVault.
 *
 * Возможности:
 *   - Уровни DEBUG / INFO / WARN / ERROR.
 *   - In-memory ring buffer (последние N записей) — источник «хвоста» лога
 *     для баг-репортов.
 *   - Персистентная запись ВСЕХ логов в каталог плагина с ротацией по размеру
 *     (log.txt + log.1.txt …), батчами с асинхронным флашем — не блокирует UI.
 *   - Дублирование в console.* для дев-режима.
 *
 * КРОСС-ПЛАТФОРМЕННОСТЬ: запись только через Obsidian adapter
 * (write/append/exists/mkdir/list/remove/read) — никаких top-level node:fs.
 * Тот же интерфейс реализуется in-memory фейком в тестах.
 *
 * ⚠️ БЕЗОПАСНОСТЬ: логгер НЕ должен получать секреты. Структурные поля
 * проходят через redactFields() — значения у ключей, похожих на секрет
 * (password/pin/key/secret/token/blob/plaintext/...), маскируются. Но первая
 * линия защиты — НЕ передавать секреты в лог вообще.
 */

export enum LogLevel {
  DEBUG = 10,
  INFO = 20,
  WARN = 30,
  ERROR = 40,
}

export const LOG_LEVEL_NAMES: Record<LogLevel, string> = {
  [LogLevel.DEBUG]: "DEBUG",
  [LogLevel.INFO]: "INFO",
  [LogLevel.WARN]: "WARN",
  [LogLevel.ERROR]: "ERROR",
};

/** Одна запись лога (структурированная). */
export interface LogEntry {
  /** ISO-8601 timestamp. */
  ts: string;
  level: LogLevel;
  /** Область/модуль, напр. "main", "shadow", "auth". */
  tag: string;
  message: string;
  /** Опциональные структурные поля (уже отредактированные). */
  fields?: Record<string, unknown>;
}

/**
 * Минимальный интерфейс файловой подсистемы, нужный логгеру.
 * Совместим с Obsidian DataAdapter (desktop + mobile) и тестовым фейком.
 * Пути — относительно корня хранилища (vault), как и у Obsidian adapter.
 */
export interface LogAdapter {
  write(path: string, data: string): Promise<void>;
  append(path: string, data: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  mkdir(path: string): Promise<void>;
  list(path: string): Promise<{ files: string[]; folders: string[] }>;
  remove(path: string): Promise<void>;
  read(path: string): Promise<string>;
  stat?(path: string): Promise<{ size: number; mtime: number } | null>;
}

export interface LoggerOptions {
  /** Каталог логов (относительно vault root). */
  logDir: string;
  /** Минимальный уровень записи (ниже — игнорируется). */
  minLevel?: LogLevel;
  /** Размер in-memory ring buffer (число записей). */
  ringSize?: number;
  /** Максимальный размер одного файла лога в байтах до ротации. */
  maxFileBytes?: number;
  /** Сколько ротированных файлов хранить (log.1.txt … log.N.txt). */
  maxFiles?: number;
  /** Интервал флаша батча в мс. */
  flushIntervalMs?: number;
  /** Дублировать в console.*. */
  mirrorConsole?: boolean;
}

const DEFAULTS = {
  minLevel: LogLevel.DEBUG,
  ringSize: 1000,
  maxFileBytes: 512 * 1024, // 512 КБ на файл
  maxFiles: 3, // log.txt + log.1.txt + log.2.txt
  flushIntervalMs: 1500,
  mirrorConsole: true,
};

/**
 * Ключи структурных полей, значения которых маскируются.
 * Срабатывает по подстроке (case-insensitive).
 */
const SENSITIVE_KEY_PATTERNS = [
  "password",
  "passwd",
  "pwd",
  "pin",
  "secret",
  "key", // masterKey, rawKey, derivedKey, deviceKey, apiKey …
  "token",
  "salt",
  "blob", // verificationBlob
  "plaintext",
  "plain",
  "mnemonic",
  "seed",
  "credential",
];

const REDACTED = "[REDACTED]";

/** true, если имя ключа похоже на секрет. */
export function isSensitiveKey(key: string): boolean {
  const k = key.toLowerCase();
  return SENSITIVE_KEY_PATTERNS.some((p) => k.includes(p));
}

/**
 * Рекурсивно маскирует значения у «чувствительных» ключей в объекте.
 * Возвращает НОВЫЙ объект (исходный не мутируется). Глубина ограничена,
 * чтобы не зациклиться на больших/циклических структурах.
 */
export function redactFields(
  input: Record<string, unknown> | undefined,
  depth = 0,
): Record<string, unknown> | undefined {
  if (!input) return input;
  if (depth > 4) return { _truncated: true };
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (isSensitiveKey(key)) {
      out[key] = REDACTED;
      continue;
    }
    out[key] = redactValue(value, depth);
  }
  return out;
}

function redactValue(value: unknown, depth: number): unknown {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean") return value;
  // Бинарные данные (потенциально plaintext/ключи) — НЕ логируем содержимое.
  if (
    value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value as ArrayBufferView)
  ) {
    const len =
      value instanceof ArrayBuffer
        ? value.byteLength
        : (value as ArrayBufferView).byteLength;
    return `[binary ${len}B]`;
  }
  if (Array.isArray(value)) {
    if (depth > 4) return "[...]";
    return value.slice(0, 50).map((v) => redactValue(v, depth + 1));
  }
  if (t === "object") {
    return redactFields(value as Record<string, unknown>, depth + 1);
  }
  return String(value);
}

/** Форматирует запись в одну строку для файла. */
export function formatEntry(e: LogEntry): string {
  const lvl = LOG_LEVEL_NAMES[e.level];
  let line = `${e.ts} [${lvl}] [${e.tag}] ${e.message}`;
  if (e.fields && Object.keys(e.fields).length > 0) {
    try {
      line += " " + JSON.stringify(e.fields);
    } catch {
      line += " {unserializable fields}";
    }
  }
  return line;
}

export class Logger {
  private readonly opts: Required<LoggerOptions>;
  private ring: LogEntry[] = [];
  private pending: string[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  /**
   * Промис текущего in-flight flush (null, если flush не идёт).
   * close() обязан его дождаться перед финальным сбросом pending —
   * иначе хвост логов, накопленный за время записи, терялся бы.
   */
  private flushPromise: Promise<void> | null = null;
  private dirEnsured = false;
  private closed = false;

  constructor(
    private readonly adapter: LogAdapter,
    options: LoggerOptions,
  ) {
    this.opts = { ...DEFAULTS, ...options };
  }

  setMinLevel(level: LogLevel): void {
    this.opts.minLevel = level;
  }

  getMinLevel(): LogLevel {
    return this.opts.minLevel;
  }

  get logDir(): string {
    return this.opts.logDir;
  }

  /** Активный файл лога. */
  get logFile(): string {
    return `${this.opts.logDir}/log.txt`;
  }

  debug(tag: string, message: string, fields?: Record<string, unknown>): void {
    this.log(LogLevel.DEBUG, tag, message, fields);
  }
  info(tag: string, message: string, fields?: Record<string, unknown>): void {
    this.log(LogLevel.INFO, tag, message, fields);
  }
  warn(tag: string, message: string, fields?: Record<string, unknown>): void {
    this.log(LogLevel.WARN, tag, message, fields);
  }
  error(tag: string, message: string, fields?: Record<string, unknown>): void {
    this.log(LogLevel.ERROR, tag, message, fields);
  }

  log(
    level: LogLevel,
    tag: string,
    message: string,
    fields?: Record<string, unknown>,
  ): void {
    if (this.closed) return;
    if (level < this.opts.minLevel) return;

    const entry: LogEntry = {
      ts: new Date().toISOString(),
      level,
      tag,
      message,
      fields: redactFields(fields),
    };

    // Ring buffer
    this.ring.push(entry);
    if (this.ring.length > this.opts.ringSize) {
      this.ring.splice(0, this.ring.length - this.opts.ringSize);
    }

    const line = formatEntry(entry);

    // Console mirror
    if (this.opts.mirrorConsole) {
      const c = `[ShadowVault] ${line}`;
      if (level >= LogLevel.ERROR) console.error(c);
      else if (level >= LogLevel.WARN) console.warn(c);
      else if (level >= LogLevel.INFO) console.info(c);
      else console.debug(c);
    }

    // Очередь на персист
    this.pending.push(line);
    this.scheduleFlush();
  }

  /** Возвращает последние N строк лога (для баг-репорта). */
  tail(n: number): string[] {
    const lines = this.ring.map(formatEntry);
    return lines.slice(Math.max(0, lines.length - n));
  }

  /** Снимок ring buffer (копия). */
  snapshot(): LogEntry[] {
    return this.ring.slice();
  }

  private scheduleFlush(): void {
    if (this.flushTimer || this.closed) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      void this.flush();
    }, this.opts.flushIntervalMs);
    // В Node-тестах не держим event loop активным из-за фонового таймера.
    (this.flushTimer as unknown as { unref?: () => void }).unref?.();
  }

  /** Принудительно сбрасывает накопленный буфер в файл. */
  async flush(): Promise<void> {
    // Flush уже идёт — дожидаемся его вместо параллельной записи в тот же
    // файл (важно для close(): вызов не должен «проваливаться» молча).
    if (this.flushPromise) {
      await this.flushPromise;
      return;
    }
    if (this.pending.length === 0) return;
    const run = this.doFlush();
    this.flushPromise = run;
    try {
      await run;
    } finally {
      this.flushPromise = null;
      // Если за время флаша накопилось ещё (или батч вернулся после ошибки) —
      // планируем следующий. При closed таймер не ставится (см. scheduleFlush):
      // остаток добирает финальный flush внутри close().
      if (this.pending.length > 0) this.scheduleFlush();
    }
  }

  /** Тело одного flush-прохода. Никогда не бросает (best-effort). */
  private async doFlush(): Promise<void> {
    const batch = this.pending;
    this.pending = [];
    try {
      await this.ensureDir();
      await this.rotateIfNeeded(batch);
      const data = batch.join("\n") + "\n";
      const file = this.logFile;
      if (await this.adapter.exists(file)) {
        await this.adapter.append(file, data);
      } else {
        await this.adapter.write(file, data);
      }
    } catch (err) {
      // Логгер не должен ронять плагин. Возвращаем батч обратно (best-effort) —
      // его подберёт следующий flush (в т.ч. финальный из close()).
      this.pending.unshift(...batch);
      // Печатаем в консоль напрямую, чтобы не рекурсировать через log().
      console.error("[ShadowVault] Logger.flush failed:", err);
    }
  }

  private async ensureDir(): Promise<void> {
    if (this.dirEnsured) return;
    if (!(await this.adapter.exists(this.opts.logDir))) {
      await this.adapter.mkdir(this.opts.logDir);
    }
    this.dirEnsured = true;
  }

  /**
   * Ротация по размеру: если активный файл + новый батч превысят лимит —
   * сдвигаем log.(N-1).txt → log.N.txt и log.txt → log.1.txt, начинаем новый.
   */
  private async rotateIfNeeded(batch: string[]): Promise<void> {
    const file = this.logFile;
    let curSize = 0;
    try {
      if (this.adapter.stat) {
        const st = await this.adapter.stat(file);
        curSize = st?.size ?? 0;
      } else if (await this.adapter.exists(file)) {
        curSize = (await this.adapter.read(file)).length;
      }
    } catch {
      curSize = 0;
    }
    const incoming = batch.reduce((s, l) => s + l.length + 1, 0);
    if (curSize + incoming <= this.opts.maxFileBytes) return;

    // Сдвиг: удаляем самый старший, поднимаем остальные.
    const oldest = `${this.opts.logDir}/log.${this.opts.maxFiles - 1}.txt`;
    try {
      if (await this.adapter.exists(oldest)) await this.adapter.remove(oldest);
    } catch {
      /* ignore */
    }
    for (let i = this.opts.maxFiles - 2; i >= 1; i--) {
      const from = `${this.opts.logDir}/log.${i}.txt`;
      const to = `${this.opts.logDir}/log.${i + 1}.txt`;
      await this.moveFile(from, to);
    }
    // log.txt → log.1.txt
    await this.moveFile(file, `${this.opts.logDir}/log.1.txt`);
  }

  /** Перемещение файла через read+write+remove (adapter может не иметь rename). */
  private async moveFile(from: string, to: string): Promise<void> {
    try {
      if (!(await this.adapter.exists(from))) return;
      const content = await this.adapter.read(from);
      await this.adapter.write(to, content);
      await this.adapter.remove(from);
    } catch (err) {
      console.error("[ShadowVault] Logger.moveFile failed:", err);
    }
  }

  /**
   * Останавливает таймер, дожидается in-flight flush и сбрасывает остаток
   * pending. Вызывать в onunload. Best-effort: никогда не бросает.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    try {
      // 1. Дожидаемся текущего in-flight flush: если он упадёт, его батч
      //    вернётся в pending (см. doFlush) и не потеряется.
      if (this.flushPromise) await this.flushPromise;
      // 2. Финальный сброс остатка pending (включая хвост, накопленный за
      //    время in-flight flush, и возвращённый после ошибки батч).
      if (this.pending.length > 0) await this.flush();
    } catch (err) {
      // Не рекурсируем через log() — прямая печать в консоль.
      console.error("[ShadowVault] Logger.close failed:", err);
    } finally {
      this.closed = true;
    }
  }

  /** Список файлов логов (для UI / очистки). */
  async listLogFiles(): Promise<string[]> {
    try {
      const { files } = await this.adapter.list(this.opts.logDir);
      return files.filter((f) => /log(\.\d+)?\.txt$/.test(f));
    } catch {
      return [];
    }
  }

  /** Удаляет все файлы логов. */
  async clear(): Promise<void> {
    this.ring = [];
    this.pending = [];
    const files = await this.listLogFiles();
    for (const f of files) {
      try {
        await this.adapter.remove(f);
      } catch {
        /* ignore */
      }
    }
  }
}
