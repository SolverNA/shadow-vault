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
    name.endsWith(".sessiontmp") ||
    name.endsWith(".retmp") ||
    name.endsWith(".enc.new")
  );
}

/**
 * Создаёт symlink target → linkPath. На Windows fs.symlink требует прав администратора
 * для symlink на директорию, поэтому на Win используем junction (работает без elevation).
 *
 * Если linkPath уже существует и указывает на target — no-op.
 * Если указывает на ДРУГОЕ — бросает ошибку (не перезаписываем чужие линки).
 */
export async function ensureSymlink(target: string, linkPath: string): Promise<void> {
  // Уже существует?
  try {
    const existing = await fsp.readlink(linkPath);
    const resolvedExisting = nodePath.resolve(nodePath.dirname(linkPath), existing);
    const resolvedTarget = nodePath.resolve(target);
    if (resolvedExisting === resolvedTarget) return;
    // Линк указывает на другое место — это ошибка состояния, не перезаписываем молча
    throw new Error(
      `[ensureSymlink] linkPath "${linkPath}" уже существует и указывает на "${resolvedExisting}", ожидалось "${resolvedTarget}"`
    );
  } catch (err) {
    // ENOENT — линка нет, идём создавать
    // EINVAL — это не симлинк (обычная папка/файл) — тоже ошибка состояния
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EINVAL") {
      throw new Error(
        `[ensureSymlink] "${linkPath}" существует но не является символьной ссылкой — нужно убрать вручную`
      );
    }
    if (code !== "ENOENT") throw err;
  }

  await fsp.mkdir(nodePath.dirname(linkPath), { recursive: true });

  // Windows-friendly: junction для директорий, symlink для файлов и не-Windows
  const isWindows = process.platform === "win32";
  const stat = await fsp.stat(target).catch(() => null);
  const type = isWindows && stat?.isDirectory() ? "junction" : (stat?.isDirectory() ? "dir" : "file");
  await fsp.symlink(target, linkPath, type);
}

/**
 * Снимает symlink (или junction). Если linkPath не симлинк — НЕ удаляем,
 * чтобы случайно не стереть рабочую папку.
 */
export async function removeSymlink(linkPath: string): Promise<void> {
  try {
    const lst = await fsp.lstat(linkPath);
    if (lst.isSymbolicLink()) {
      await fsp.unlink(linkPath);
    }
    // Не симлинк → ничего не делаем (защита от случайного удаления данных)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
}

/**
 * Параллельный map с ограниченной concurrency — обрабатывает items одновременно
 * не более чем `concurrency` штук. Сохраняет порядок результатов.
 *
 * Используется в bulk-операциях шифрования: AES-GCM нельзя распараллелить
 * внутри одного файла (auth tag покрывает весь поток), но несколько файлов
 * можно гонять одновременно — node:crypto использует hardware AES,
 * I/O идёт через Node's libuv thread pool.
 *
 * @param items        Список элементов для обработки
 * @param concurrency  Сколько одновременно (>=1)
 * @param fn           async-функция обработки одного элемента
 * @param onItemDone   Опц. колбэк при завершении каждого элемента —
 *                     вызывается после resolve/reject, последовательно
 *                     (не параллельно), для безопасного обновления UI/счётчиков.
 */
export async function parallelMap<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
  onItemDone?: (index: number, result: R) => void
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;

  const worker = async (): Promise<void> => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      const r = await fn(items[i], i);
      results[i] = r;
      onItemDone?.(i, r);
    }
  };

  const workers = Array.from(
    { length: Math.max(1, Math.min(concurrency, items.length)) },
    () => worker()
  );
  await Promise.all(workers);
  return results;
}

/**
 * Сравнивает содержимое двух файлов поблочно. Возвращает true если они идентичны.
 * Используется для верификации что расшифровка дала тот же plaintext, который был зашифрован.
 */
export async function filesEqual(pathA: string, pathB: string): Promise<boolean> {
  const [statA, statB] = await Promise.all([
    fsp.stat(pathA).catch(() => null),
    fsp.stat(pathB).catch(() => null),
  ]);
  if (!statA || !statB) return false;
  if (statA.size !== statB.size) return false;
  if (statA.size === 0) return true;

  const [bufA, bufB] = await Promise.all([fsp.readFile(pathA), fsp.readFile(pathB)]);
  return bufA.equals(bufB);
}
