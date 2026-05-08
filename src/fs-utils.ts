/**
 * Общие утилиты файловой системы и константы формата зашифрованных файлов.
 * Единственный источник правды — чтобы избежать копипасты в session/shadow/main.
 */

import * as fsp from "fs/promises";
import * as nodePath from "path";

/** Размер криптографического заголовка: IV (12 б) + AuthTag (16 б) */
export const CRYPTO_HEADER_SIZE = 28;

/** Суффикс зашифрованных файлов в оригинальном хранилище */
export const ENCRYPTED_EXT = ".enc";

/** Возвращает true если по абсолютному пути существует файл/папка */
export async function fileExists(absPath: string): Promise<boolean> {
  try {
    await fsp.access(absPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Атомарная запись через временный файл и rename.
 * Гарантирует что absPath либо содержит старые данные, либо новые — не половину.
 */
export async function atomicWrite(
  absPath: string,
  data: Buffer,
  tmpExt = ".shadowtmp"
): Promise<void> {
  await fsp.mkdir(nodePath.dirname(absPath), { recursive: true });
  const tmpPath = absPath + tmpExt;
  try {
    await fsp.writeFile(tmpPath, data);
    await fsp.rename(tmpPath, absPath);
  } catch (err) {
    await fsp.unlink(tmpPath).catch(() => undefined);
    throw err;
  }
}

/** true если имя — временный файл атомарной записи (наш или из других модулей) */
export function isTempFile(name: string): boolean {
  return (
    name.endsWith(".tmp") ||
    name.endsWith(".shadowtmp") ||
    name.endsWith(".sessiontmp")
  );
}
