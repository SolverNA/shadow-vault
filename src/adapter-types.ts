/**
 * Минимальные интерфейсы Obsidian DataAdapter, необходимые ShadowVaultManager.
 * Определены локально, чтобы тесты не зависели от пакета obsidian.
 *
 * Источник: https://github.com/obsidianmd/obsidian-api/blob/master/obsidian.d.ts
 */

export interface DataWriteOptions {
  /** Время создания файла (мс, Unix timestamp). Опционально. */
  ctime?: number;
  /** Время изменения файла (мс, Unix timestamp). Опционально. */
  mtime?: number;
}

/** Метаданные файла/папки — аналог fs.Stats, но упрощённый */
export interface AdapterStat {
  type: "file" | "folder";
  ctime: number; // ms
  mtime: number; // ms
  size: number;  // байт
}

/** Результат list() — разделённые файлы и папки */
export interface ListedFiles {
  files: string[];   // normalizedPath[]
  folders: string[]; // normalizedPath[]
}

/**
 * Интерфейс файлового адаптера Obsidian (десктоп — FileSystemAdapter).
 * Все пути — normalizedPath: относительные, через '/', без ведущего '/'.
 */
export interface IDataAdapter {
  // ── Чтение ──────────────────────────────────────────────────────────────
  read(normalizedPath: string): Promise<string>;
  readBinary(normalizedPath: string): Promise<ArrayBuffer>;
  // ── Запись ──────────────────────────────────────────────────────────────
  write(normalizedPath: string, data: string, options?: DataWriteOptions): Promise<void>;
  writeBinary(normalizedPath: string, data: ArrayBuffer, options?: DataWriteOptions): Promise<void>;
  append(normalizedPath: string, data: string, options?: DataWriteOptions): Promise<void>;
  process(normalizedPath: string, fn: (data: string) => string, options?: DataWriteOptions): Promise<string>;
  // ── Мета ────────────────────────────────────────────────────────────────
  exists(normalizedPath: string, sensitive?: boolean): Promise<boolean>;
  stat(normalizedPath: string): Promise<AdapterStat | null>;
  list(normalizedPath: string): Promise<ListedFiles>;
  // ── Структура ───────────────────────────────────────────────────────────
  mkdir(normalizedPath: string): Promise<void>;
  remove(normalizedPath: string): Promise<void>;
  rename(normalizedPath: string, newNormalizedPath: string): Promise<void>;
  copy(normalizedPath: string, newNormalizedPath: string): Promise<void>;
  trashSystem(normalizedPath: string): Promise<boolean>;
  trashLocal(normalizedPath: string): Promise<void>;
  // ── Специфично для FileSystemAdapter ────────────────────────────────────
  getBasePath(): string;
  getResourcePath(normalizedPath: string): string;
}
