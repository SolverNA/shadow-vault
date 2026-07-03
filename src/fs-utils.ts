/**
 * Общие утилиты файловой системы и константы формата зашифрованных файлов.
 * Единственный источник правды — чтобы избежать копипасты в session/shadow/main.
 *
 * MOBILE-SAFE: модуль импортируется и из main.ts (грузится на обеих платформах),
 * поэтому НЕ имеет top-level node-импортов. Константы и чистые функции
 * (ENCRYPTED_EXT, isTempFile, parallelMap) работают везде; fs-зависимые функции
 * берут node-модули лениво через node-fs (вызываются только на desktop).
 */

import { nfs, nfsp, npath } from "./node-fs";

/**
 * Постоянный размер служебных данных контейнера v2:
 *   MAGIC+version (5 б) + IV (12 б) + GCM-tag (16 б) = 33 б.
 * Используется для компенсации размера .enc в stat().
 */
export const CRYPTO_HEADER_SIZE = 33;

/** Суффикс зашифрованных файлов в оригинальном хранилище */
export const ENCRYPTED_EXT = ".enc";

/**
 * Допуск (мс) при сравнении mtime shadow-файла с mtime его .enc: shadow
 * считается «несхороненным», если shadow.mtime > enc.mtime + допуск.
 * Единая константа для sync-дошифровки при закрытии (shadow-vault-manager)
 * и crash recovery (session-manager) — раньше значения расходились в 20 раз
 * (1000 мс против 50 мс), и секундный допуск открывал окно тихой потери
 * правки, сделанной менее чем за 1 с до закрытия Obsidian.
 *
 * Почему именно 50 мс, а не строгое сравнение (0):
 *   - .enc всегда пишется ПОСЛЕ shadow (encryptOne читает shadow → пишет .enc),
 *     поэтому у реально дошифрованного файла enc.mtime >= shadow.mtime;
 *   - но ensureDecrypted() копирует mtime .enc в shadow через utimes, и
 *     round-trip stat→utimes→stat (double-секунды libuv ↔ наносекунды ФС)
 *     может сдвинуть shadow.mtime на доли мс В ОБЕ стороны. Строгое сравнение
 *     тогда пометило бы каждый расшифрованный, но не изменённый файл как
 *     «несхороненный» → полная пере-шифровка vault при каждом закрытии.
 *   50 мс с запасом гасят эту погрешность, но на порядки меньше любого
 *   реального интервала «autosave → закрытие окна».
 */
export const MTIME_TOLERANCE_MS = 50;

/** Возвращает true если по абсолютному пути существует файл/папка */
export async function fileExists(absPath: string): Promise<boolean> {
  try {
    await nfsp().access(absPath);
    return true;
  } catch {
    return false;
  }
}

/** Уникальный tmp-путь для атомарной записи (PID + время + случайный хвост). */
function makeTmpPath(absPath: string, tmpExt: string): string {
  const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return absPath + "." + unique + tmpExt;
}

/**
 * Best-effort fsync каталога — фиксирует rename в журнале ФС.
 * Без него при power-loss rename может «пережить» сбой, а сами данные — нет.
 *
 * На Windows открыть каталог для fsync нельзя (EPERM/EISDIR/EBADF в зависимости
 * от версии Node/ОС), поэтому любые ошибки глотаются: это усиление durability,
 * а не условие корректности записи.
 */
async function fsyncDirBestEffort(dirPath: string): Promise<void> {
  const fsp = nfsp();
  try {
    const dh = await fsp.open(dirPath, "r");
    try {
      await dh.sync();
    } finally {
      await dh.close();
    }
  } catch {
    // Windows и экзотические ФС: fsync каталога не поддерживается — игнор.
  }
}

/** Синхронный аналог fsyncDirBestEffort — для sync-пути закрытия Obsidian. */
function fsyncDirSyncBestEffort(dirPath: string): void {
  const fs = nfs();
  try {
    const fd = fs.openSync(dirPath, "r");
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // Windows: fsync каталога не поддерживается (EPERM/EISDIR/EBADF) — игнор.
  }
}

/**
 * Атомарная запись через временный файл и rename.
 * Гарантирует что absPath либо содержит старые данные, либо новые — не половину.
 *
 * Durability при power-loss: перед rename делается fsync tmp-файла (данные
 * попадают на диск ДО того, как rename станет видимым), после rename —
 * best-effort fsync каталога (сам rename фиксируется в журнале ФС). Без этого
 * журналируемая ФС может зафиксировать rename раньше данных, и после сбоя
 * питания на месте валидного файла остаётся пустой/усечённый.
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
  const dir = npath().dirname(absPath);
  await fsp.mkdir(dir, { recursive: true });
  const tmpPath = makeTmpPath(absPath, tmpExt);
  try {
    const fh = await fsp.open(tmpPath, "w");
    try {
      await fh.writeFile(data);
      await fh.sync(); // данные на диске ДО rename
    } finally {
      await fh.close();
    }
    await fsp.rename(tmpPath, absPath);
  } catch (err) {
    await fsp.unlink(tmpPath).catch(() => undefined);
    throw err;
  }
  await fsyncDirBestEffort(dir);
}

/**
 * Синхронный вариант atomicWrite — для путей, где await недоступен
 * (дошифровка при закрытии Obsidian, см. encryptUnsyncedChangesSync).
 * Семантика и durability-гарантии идентичны async-версии.
 */
export function atomicWriteSync(
  absPath: string,
  data: Buffer,
  tmpExt = ".shadowtmp"
): void {
  const fs = nfs();
  const dir = npath().dirname(absPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = makeTmpPath(absPath, tmpExt);
  try {
    const fd = fs.openSync(tmpPath, "w");
    try {
      let offset = 0;
      while (offset < data.length) {
        offset += fs.writeSync(fd, data, offset, data.length - offset);
      }
      fs.fsyncSync(fd); // данные на диске ДО rename
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, absPath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      /* tmp мог не создаться */
    }
    throw err;
  }
  fsyncDirSyncBestEffort(dir);
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
 * true если запись каталога — СЛУЖЕБНЫЙ артефакт (не пользовательские данные)
 * и должна исключаться из всех сканов shadow/original: encrypt-back,
 * bulk decrypt, sync-дошифровка при закрытии и crash recovery.
 *
 * ЕДИНЫЙ источник правды для фильтров сканеров. Симметрия критична:
 * если encrypt-back видит путь, а decrypt/recovery — нет (или наоборот),
 * появляется односторонняя утечка данных между хранилищами.
 *
 * Служебное:
 *   - configDir (.obsidian) — конфиг живёт в оригинале и доступен из shadow
 *     через symlink, его нельзя ни шифровать, ни сканировать;
 *   - .session_active — legacy-маркер сессии в корне оригинала (до v1.1.0);
 *   - .DS_Store — мусор Finder (macOS), не переносим между хранилищами;
 *   - .shadow-vault-* — сам теневой каталог (защита, если он оказался
 *     внутри сканируемого дерева);
 *   - временные файлы атомарной записи (см. isTempFile).
 *
 * Всё остальное — включая ПОЛЬЗОВАТЕЛЬСКИЕ dot-пути (.trash, .git от
 * obsidian-git и т.п.) — данные пользователя: шифруются в оригинал и
 * восстанавливаются в shadow наравне с обычными файлами.
 */
export function isServiceEntryName(name: string, configDir: string): boolean {
  return (
    name === configDir ||
    name === ".session_active" ||
    name === ".DS_Store" ||
    name.startsWith(".shadow-vault-") ||
    isTempFile(name)
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
