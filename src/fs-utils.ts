/**
 * Общие утилиты файловой системы и константы формата зашифрованных файлов.
 * Единственный источник правды — чтобы избежать копипасты в session/shadow/main.
 *
 * MOBILE-SAFE: модуль импортируется и из main.ts (грузится на обеих платформах),
 * поэтому НЕ имеет top-level node-импортов. Константы и чистые функции
 * (ENCRYPTED_EXT, isTempFile, parallelMap) работают везде; fs-зависимые функции
 * берут node-модули лениво через node-fs (вызываются только на desktop).
 */

import { nfsp, npath } from "./node-fs";

/**
 * Постоянный размер служебных данных контейнера v2:
 *   MAGIC+version (5 б) + IV (12 б) + GCM-tag (16 б) = 33 б.
 * Используется для компенсации размера .enc в stat().
 */
export const CRYPTO_HEADER_SIZE = 33;

/** Суффикс зашифрованных файлов в оригинальном хранилище */
export const ENCRYPTED_EXT = ".enc";

/** Возвращает true если по абсолютному пути существует файл/папка */
export async function fileExists(absPath: string): Promise<boolean> {
  try {
    await nfsp().access(absPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Атомарная запись через временный файл и rename.
 * Гарантирует что absPath либо содержит старые данные, либо новые — не половину.
 *
 * Уникальный tmp-suffix (с PID + случайным хвостом) защищает от race condition
 * когда два параллельных atomicWrite на одном файле дрались за `.shadowtmp` —
 * второй writeFile перетирал tmp первого, потом первый rename перемещал чужие
 * данные на target, второй rename падал с ENOENT, итог — повреждённый файл.
 */
export async function atomicWrite(
  absPath: string,
  data: Buffer,
  tmpExt = ".shadowtmp"
): Promise<void> {
  const fsp = nfsp();
  await fsp.mkdir(npath().dirname(absPath), { recursive: true });
  const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tmpPath = absPath + "." + unique + tmpExt;
  try {
    await fsp.writeFile(tmpPath, data);
    await fsp.rename(tmpPath, absPath);
  } catch (err) {
    await fsp.unlink(tmpPath).catch(() => undefined);
    throw err;
  }
}

/** Запись каталога для visitor'а walkDir: относительный путь (через "/") + тип. */
export interface WalkEntry {
  /** Путь относительно корня обхода, разделитель "/" (например "sub/note"). */
  rel: string;
  /** Имя самой записи (без префикса каталога). */
  name: string;
  isDirectory: boolean;
  isFile: boolean;
}

/**
 * Универсальный рекурсивный обход каталога (desktop, Node fs).
 * Единый сканер вместо копий в shadow-vault-manager/main — устраняет
 * дублирование «readdir + правила пропуска + рекурсия».
 *
 * @param absRoot  Абсолютный корень обхода.
 * @param visit    Колбэк на каждую запись. Возвращает:
 *                   - "recurse"  — зайти внутрь каталога (для файлов игнор.);
 *                   - "skip"     — не заходить внутрь / не учитывать;
 *                 Для файлов важен только сам факт вызова visit (внутрь не идём).
 * @param relDir   Внутренний параметр рекурсии — не передавать снаружи.
 *
 * Ошибки readdir (ENOENT/недоступность) трактуются как пустой каталог.
 */
export async function walkDir(
  absRoot: string,
  visit: (entry: WalkEntry) => "recurse" | "skip",
  relDir = ""
): Promise<void> {
  const nodePath = npath();
  const absDir = relDir
    ? nodePath.join(absRoot, ...relDir.split("/"))
    : absRoot;

  let entries: import("fs").Dirent[];
  try {
    entries = await nfsp().readdir(absDir, { withFileTypes: true });
  } catch {
    return;
  }

  const prefix = relDir ? relDir + "/" : "";
  for (const e of entries) {
    const rel = prefix + e.name;
    const isDirectory = e.isDirectory();
    const decision = visit({ rel, name: e.name, isDirectory, isFile: e.isFile() });
    if (isDirectory && decision === "recurse") {
      await walkDir(absRoot, visit, rel);
    }
  }
}

/**
 * Транслирует один уровень каталога оригинального хранилища в вид, который
 * ожидает Obsidian: .enc-файлы → имена без суффикса, dot/временные пропускаются.
 *
 * Единый источник правды для list-патча — раньше та же логика была скопирована
 * в main.patchListEarly и ShadowVaultManager.patchedList.
 *
 * @param absDir         Абсолютный каталог в оригинальном хранилище.
 * @param normalizedPath Путь каталога относительно корня vault ("" для корня).
 * @param configDir      Имя каталога конфигурации (.obsidian) — не скрываем его.
 */
export async function listEncryptedDir(
  absDir: string,
  normalizedPath: string,
  configDir: string
): Promise<{ files: string[]; folders: string[] }> {
  const files: string[] = [];
  const folders: string[] = [];

  let entries: import("fs").Dirent[];
  try {
    entries = await nfsp().readdir(absDir, { withFileTypes: true });
  } catch {
    return { files: [], folders: [] };
  }

  const prefix = normalizedPath ? normalizedPath + "/" : "";
  for (const entry of entries) {
    // Скрытые файлы (.session_active и т.п.) — не показываем, кроме configDir
    if (entry.name.startsWith(".") && entry.name !== configDir) continue;
    if (isTempFile(entry.name)) continue;

    if (entry.isDirectory()) {
      folders.push(prefix + entry.name);
    } else if (entry.isFile() && entry.name.endsWith(ENCRYPTED_EXT)) {
      files.push(prefix + entry.name.slice(0, -ENCRYPTED_EXT.length));
    }
    // Не-.enc файлы в оригинале не показываем (системные/немигрированные)
  }

  return { files, folders };
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
  const fsp = nfsp();
  const nodePath = npath();
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
  const fsp = nfsp();
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
  const fsp = nfsp();
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
