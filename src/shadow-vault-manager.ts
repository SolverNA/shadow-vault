/**
 * ShadowVaultManager — ядро VFS-слоя плагина ShadowVault.
 *
 * Два физических хранилища:
 *   Оригинальное  (originalRoot) — зашифрованные файлы формата <name>.<ext>.enc
 *   Теневое       (shadowRoot)   — расшифрованные файлы <name>.<ext>, рядом с оригинальным,
 *                                  НЕ внутри него: parentDir/.shadow-vault-<hash>
 *
 * Маршрутизация:
 *   ┌──────────────────────────────────────────────────────────────────┐
 *   │  normalizedPath начинается с '.obsidian'?                        │
 *   │       ДА  →  оригинальный адаптер без изменений                 │
 *   │       НЕТ →  read  из shadow (lazy decrypt от оригинала)        │
 *   │              write в shadow + немедленное шифрование в оригинал │
 *   └──────────────────────────────────────────────────────────────────┘
 *
 * Формат зашифрованных файлов в originalRoot:
 *   note.md  →  note.md.enc    (IV 12б + AuthTag 16б + шифртекст)
 *   img.png  →  img.png.enc
 *
 * Obsidian при вызове list() получает пути БЕЗ суффикса .enc, т.е. видит "note.md".
 * Все внутренние операции (ensureDecrypted, write-through) добавляют .enc сами.
 */

import * as fs from "fs";
import * as fsp from "fs/promises";
import * as nodePath from "path";
import * as crypto from "crypto";
import * as os from "os";
import { CryptoEngine } from "./crypto-engine";
import { IDataAdapter, AdapterStat, DataWriteOptions, ListedFiles } from "./adapter-types";
import {
  CRYPTO_HEADER_SIZE,
  ENCRYPTED_EXT,
  atomicWrite,
  ensureSymlink,
  fileExists,
  filesEqual,
  isTempFile,
  parallelMap,
  removeSymlink,
} from "./fs-utils";

/**
 * Параллелизм bulk-операций.
 * Берём min(8, max(2, cpus-1)) — оставляем CPU для UI Obsidian'а на слабом железе.
 * 8 — практический потолок: дальше упираемся в I/O, а не в CPU.
 */
function bulkConcurrency(): number {
  const cpus = os.cpus()?.length ?? 4;
  return Math.max(2, Math.min(8, cpus - 1));
}

export class ShadowVaultManager {
  private readonly engine: CryptoEngine;
  /** Абсолютный путь к оригинальному (зашифрованному) хранилищу */
  readonly originalRoot: string;
  /** Абсолютный путь к теневому (расшифрованному) хранилищу */
  readonly shadowRoot: string;

  private patched = false;
  private originalMethods: Partial<IDataAdapter> = {};
  private readonly configDir: string;

  /** Сохранённое значение adapter.basePath ДО mount — для отката при unmount */
  private originalBasePath: string | null = null;
  /** Сохранённый getResourcePath ДО подмены — для отката при unmount */
  private originalGetResourcePath: ((normalizedPath: string) => string) | null = null;
  /** Сохранённый getBasePath ДО подмены — для отката при unmount */
  private originalGetBasePath: (() => string) | null = null;
  /** true пока shadow примонтирован как basePath адаптера */
  private mounted = false;

  constructor(engine: CryptoEngine, originalRoot: string, shadowRoot?: string, configDir = ".obsidian") {
    this.engine = engine;
    this.originalRoot = nodePath.normalize(originalRoot);
    this.configDir = configDir;

    if (shadowRoot) {
      this.shadowRoot = nodePath.normalize(shadowRoot);
    } else {
      // Теневое хранилище — РЯДОМ с оригинальным, не внутри.
      // Детерминированное имя на базе хеша пути: важно для crash recovery после перезапуска.
      const vaultHash = crypto
        .createHash("sha256")
        .update(this.originalRoot)
        .digest("hex")
        .slice(0, 16);
      this.shadowRoot = nodePath.join(
        nodePath.dirname(this.originalRoot),
        ".shadow-vault-" + vaultHash
      );
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Инициализация
  // ═══════════════════════════════════════════════════════════════════════

  async initialize(): Promise<void> {
    await fsp.mkdir(this.shadowRoot, { recursive: true });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Mount/unmount: shadow становится basePath адаптера Obsidian
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Монтирует shadow vault как basePath адаптера. После этого:
   *   - adapter.getBasePath() возвращает shadowRoot
   *   - adapter.getResourcePath(p) возвращает app://-URL указывающий внутрь shadow
   *     (чем рендерятся изображения, PDF и другие attachment'ы)
   *
   * Не трогает методы адаптера — они уже пропатчены через patch().
   *
   * После mount необходимо вызвать setupObsidianSymlink() чтобы конфиг был доступен.
   */
  mount(adapter: IDataAdapter): void {
    if (this.mounted) return;

    const adapterAny = adapter as unknown as { basePath?: string };

    this.originalBasePath = adapterAny.basePath ?? adapter.getBasePath();
    this.originalGetBasePath = adapter.getBasePath.bind(adapter);
    this.originalGetResourcePath = adapter.getResourcePath.bind(adapter);

    // Подменяем basePath на shadow — все нативные fs-операции внутри адаптера
    // (которые используют this.basePath) будут работать с shadow.
    adapterAny.basePath = this.shadowRoot;
    adapter.getBasePath = () => this.shadowRoot;

    // getResourcePath собирает app://-URL из basePath. После подмены basePath он
    // автоматически вернёт URL на shadow, но чтобы не зависеть от внутренней
    // реализации адаптера, явно перевычисляем через сохранённый original.
    adapter.getResourcePath = (normalizedPath: string): string => {
      // Конфиг отдаём через оригинал — он symlink'нут, но Obsidian может
      // обращаться по абсолютному пути напрямую
      if (this.isBypassPath(normalizedPath)) {
        return this.originalGetResourcePath!(normalizedPath);
      }
      // Базовый путь уже подменён, оригинальный getResourcePath вернёт URL на shadow
      return this.originalGetResourcePath!(normalizedPath);
    };

    this.mounted = true;
  }

  unmount(adapter: IDataAdapter): void {
    if (!this.mounted) return;

    const adapterAny = adapter as unknown as { basePath?: string };
    if (this.originalBasePath !== null) {
      adapterAny.basePath = this.originalBasePath;
    }
    if (this.originalGetBasePath) {
      adapter.getBasePath = this.originalGetBasePath;
    }
    if (this.originalGetResourcePath) {
      adapter.getResourcePath = this.originalGetResourcePath;
    }

    this.originalBasePath = null;
    this.originalGetBasePath = null;
    this.originalGetResourcePath = null;
    this.mounted = false;
  }

  /**
   * Создаёт в shadow символическую ссылку .obsidian → originalRoot/.obsidian.
   * Конфиг плагинов, тем и workspace'а персистится напрямую в оригинал — без шифрования.
   * Это нужно потому что Obsidian читает .obsidian ДО того как наш плагин загрузится:
   * шифровать config невозможно без bootstrap-парадокса.
   */
  async setupObsidianSymlink(): Promise<void> {
    const origConfig = nodePath.join(this.originalRoot, this.configDir);
    const shadowConfig = nodePath.join(this.shadowRoot, this.configDir);

    // Гарантируем что папка конфига существует в оригинале
    await fsp.mkdir(origConfig, { recursive: true });

    // Если в shadow на этом месте лежит обычная папка (от прошлой неудачной сессии) —
    // удаляем её рекурсивно, чтобы не конфликтовало с symlink
    try {
      const lst = await fsp.lstat(shadowConfig);
      if (lst.isDirectory() && !lst.isSymbolicLink()) {
        await fsp.rm(shadowConfig, { recursive: true, force: true });
      }
    } catch { /* нет — отлично, создадим линк ниже */ }

    await ensureSymlink(origConfig, shadowConfig);
  }

  async teardownObsidianSymlink(): Promise<void> {
    const shadowConfig = nodePath.join(this.shadowRoot, this.configDir);
    await removeSymlink(shadowConfig);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Bulk decrypt: расшифровываем весь оригинал в shadow при unlock
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Расшифровывает все .enc файлы из originalRoot в shadowRoot.
   * Вызывается ОДИН РАЗ при unlock — после этого Obsidian работает в shadow натив но.
   *
   * Гарантии надёжности:
   *   - Каждый файл расшифровывается через decryptStream (atomic write через .tmp).
   *   - Auth Tag GCM проверяется при final() → ловим повреждённые .enc сразу.
   *   - Если расшифровка одного файла провалилась — продолжаем остальные, не падаем.
   *   - Failed-список возвращается наверх для уведомления пользователя.
   */
  async decryptAllToShadow(
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<{ decrypted: string[]; failed: Array<{ path: string; error: string }> }> {
    const encFiles = await this.scanEncryptedFiles();
    const decrypted: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];
    const concurrency = bulkConcurrency();

    console.debug(`[ShadowVault] Bulk decrypt: ${encFiles.length} файлов, concurrency=${concurrency}`);

    let done = 0;
    await parallelMap(
      encFiles,
      concurrency,
      async (normalizedPath): Promise<{ ok: true } | { ok: false; error: string }> => {
        try {
          await this.ensureDecrypted(normalizedPath);
          return { ok: true };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`[ShadowVault] decryptAllToShadow: "${normalizedPath}" failed:`, err);
          return { ok: false, error: msg };
        }
      },
      (index, result) => {
        const path = encFiles[index];
        if (result.ok) decrypted.push(path);
        else failed.push({ path, error: result.error });
        done++;
        onProgress?.(done, encFiles.length, path);
      }
    );

    onProgress?.(encFiles.length, encFiles.length, "");
    console.debug(`[ShadowVault] Bulk decrypt done: ${decrypted.length} ok, ${failed.length} failed`);
    return { decrypted, failed };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Bulk encrypt-back: при shutdown переносим изменения из shadow в оригинал
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Сравнивает shadow и оригинал, шифрует и переносит в оригинал все файлы,
   * которые изменились в shadow относительно расшифрованной версии оригинала.
   *
   * Гарантии надёжности:
   *   - Шифрование идёт через atomic write (.enc.new → rename .enc).
   *   - Старый .enc сохраняется до успешной записи нового → нет окна потери данных.
   *   - После записи нового .enc — верифицируем decrypt-back и сравниваем с shadow.
   *     Если сходится → удаляем backup. Если нет → откатываемся к старому .enc.
   *   - Сравнение «изменился ли файл» — побайтовое (filesEqual), не по mtime.
   *     mtime ненадёжен при копировании/sync.
   */
  async encryptShadowChangesToOriginal(
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<{ encrypted: string[]; failed: Array<{ path: string; error: string }> }> {
    const encrypted: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];

    const shadowFiles = await this.scanShadowFilesForSync();
    const concurrency = bulkConcurrency();
    console.debug(`[ShadowVault] encrypt-back: ${shadowFiles.length} файлов, concurrency=${concurrency}`);

    let done = 0;
    await parallelMap(
      shadowFiles,
      concurrency,
      async (normalizedPath): Promise<"unchanged" | "encrypted" | { failed: string }> => {
        try {
          const changed = await this.shadowFileChanged(normalizedPath);
          if (!changed) return "unchanged";
          await this.encryptShadowToOriginalVerified(normalizedPath);
          return "encrypted";
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`[ShadowVault] encrypt-back: "${normalizedPath}" failed:`, err);
          return { failed: msg };
        }
      },
      (index, result) => {
        const path = shadowFiles[index];
        if (result === "encrypted") encrypted.push(path);
        else if (typeof result === "object") failed.push({ path, error: result.failed });
        done++;
        onProgress?.(done, shadowFiles.length, path);
      }
    );

    onProgress?.(shadowFiles.length, shadowFiles.length, "");
    console.debug(`[ShadowVault] encrypt-back done: ${encrypted.length} encrypted, ${failed.length} failed`);
    return { encrypted, failed };
  }

  /**
   * Шифрует shadow→оригинал с верификацией: после записи нового .enc
   * расшифровываем его и сравниваем побайтово с исходным shadow-файлом.
   * Только если совпало — атомарно заменяем старый .enc.
   *
   * Старый .enc хранится как .enc.bak до успеха, чтобы при любой ошибке
   * откатиться без потери данных.
   */
  private async encryptShadowToOriginalVerified(normalizedPath: string): Promise<void> {
    const shadowAbsPath = this.shadowAbs(normalizedPath);
    const encAbsPath = this.originalEncAbs(normalizedPath);
    const encNewPath = encAbsPath + ".new";
    const encBakPath = encAbsPath + ".bak";
    const verifyTmpPath = shadowAbsPath + ".verify";

    await fsp.mkdir(nodePath.dirname(encAbsPath), { recursive: true });

    // 1. Шифруем shadow → .enc.new
    const stat = await fsp.stat(shadowAbsPath);
    if (stat.size === 0) {
      await fsp.writeFile(encNewPath, Buffer.alloc(0));
    } else if (stat.size > 4 * 1024 * 1024) {
      await this.engine.encryptStream(shadowAbsPath, encNewPath);
    } else {
      const plain = await fsp.readFile(shadowAbsPath);
      const enc = this.engine.encryptBuffer(plain);
      await fsp.writeFile(encNewPath, enc);
    }

    // 2. Верификация: decrypt(.enc.new) === shadow?
    try {
      if (stat.size === 0) {
        const verifyStat = await fsp.stat(encNewPath);
        if (verifyStat.size !== 0) {
          throw new Error("Размер .enc.new для пустого файла не равен 0");
        }
      } else {
        await this.engine.decryptStream(encNewPath, verifyTmpPath);
        const ok = await filesEqual(shadowAbsPath, verifyTmpPath);
        if (!ok) {
          throw new Error("Verify failed: decrypt(.enc.new) != shadow");
        }
      }
    } catch (err) {
      // Откат: убираем .enc.new и .verify
      await fsp.unlink(encNewPath).catch(() => undefined);
      await fsp.unlink(verifyTmpPath).catch(() => undefined);
      throw err;
    } finally {
      await fsp.unlink(verifyTmpPath).catch(() => undefined);
    }

    // 3. Атомарная замена .enc → .enc.bak → .enc.new → .enc
    if (await fileExists(encAbsPath)) {
      await fsp.rename(encAbsPath, encBakPath);
    }
    try {
      await fsp.rename(encNewPath, encAbsPath);
    } catch (err) {
      // Не получилось — восстанавливаем backup
      if (await fileExists(encBakPath)) {
        await fsp.rename(encBakPath, encAbsPath).catch(() => undefined);
      }
      throw err;
    }

    // 4. Backup больше не нужен — новая версия верифицирована
    await fsp.unlink(encBakPath).catch(() => undefined);
  }

  /**
   * true если содержимое shadow-файла отличается от расшифрованного оригинала.
   * Сравнение побайтовое — не зависит от mtime. Если оригинал не существует — считаем изменённым.
   */
  private async shadowFileChanged(normalizedPath: string): Promise<boolean> {
    const shadowAbsPath = this.shadowAbs(normalizedPath);
    const encAbsPath = this.originalEncAbs(normalizedPath);

    if (!(await fileExists(encAbsPath))) {
      // Файл создан в shadow и ещё не зашифрован — точно изменён
      return true;
    }

    // Расшифровываем оригинал во временный файл и сравниваем
    const verifyPath = shadowAbsPath + ".cmp";
    try {
      const encStat = await fsp.stat(encAbsPath);
      if (encStat.size === 0) {
        const shadowStat = await fsp.stat(shadowAbsPath);
        return shadowStat.size !== 0;
      }
      await this.engine.decryptStream(encAbsPath, verifyPath);
      const equal = await filesEqual(shadowAbsPath, verifyPath);
      return !equal;
    } finally {
      await fsp.unlink(verifyPath).catch(() => undefined);
    }
  }

  /**
   * Рекурсивно собирает все обычные файлы в shadow для encrypt-back.
   * Пропускает .obsidian (symlink → оригинал, не шифруется),
   * скрытые файлы и временные .tmp/.shadowtmp.
   */
  private async scanShadowFilesForSync(relDir = ""): Promise<string[]> {
    const result: string[] = [];
    const absDir = relDir
      ? nodePath.join(this.shadowRoot, ...relDir.split("/"))
      : this.shadowRoot;

    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(absDir, { withFileTypes: true });
    } catch {
      return result;
    }

    const prefix = relDir ? relDir + "/" : "";
    for (const entry of entries) {
      // .obsidian — symlink на оригинал, его шифровать не надо
      if (entry.name === this.configDir) continue;
      // Скрытые/служебные
      if (entry.name.startsWith(".")) continue;
      // Временные файлы атомарных операций
      if (isTempFile(entry.name)) continue;

      const rel = prefix + entry.name;
      if (entry.isDirectory()) {
        result.push(...await this.scanShadowFilesForSync(rel));
      } else if (entry.isFile()) {
        result.push(rel);
      }
    }
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Monkey-patching
  // ═══════════════════════════════════════════════════════════════════════

  patch(adapter: IDataAdapter): void {
    if (this.patched) return;

    const orig = this.originalMethods;
    orig.read        = adapter.read.bind(adapter);
    orig.readBinary  = adapter.readBinary.bind(adapter);
    orig.write       = adapter.write.bind(adapter);
    orig.writeBinary = adapter.writeBinary.bind(adapter);
    orig.append      = adapter.append.bind(adapter);
    orig.process     = adapter.process.bind(adapter);
    orig.exists      = adapter.exists.bind(adapter);
    orig.stat        = adapter.stat.bind(adapter);
    orig.list        = adapter.list.bind(adapter);
    orig.mkdir       = adapter.mkdir.bind(adapter);
    orig.remove      = adapter.remove.bind(adapter);
    orig.rename      = adapter.rename.bind(adapter);
    orig.copy        = adapter.copy.bind(adapter);
    orig.trashSystem = adapter.trashSystem.bind(adapter);
    orig.trashLocal  = adapter.trashLocal.bind(adapter);

    adapter.read        = (p)        => this.patchedRead(p);
    adapter.readBinary  = (p)        => this.patchedReadBinary(p);
    adapter.write       = (p, d, o)  => this.patchedWrite(p, d, o);
    adapter.writeBinary = (p, d, o)  => this.patchedWriteBinary(p, d, o);
    adapter.append      = (p, d, o)  => this.patchedAppend(p, d, o);
    adapter.process     = (p, fn, o) => this.patchedProcess(p, fn, o);
    adapter.exists      = (p, s)     => this.patchedExists(p, s);
    adapter.stat        = (p)        => this.patchedStat(p);
    adapter.list        = (p)        => this.patchedList(p);
    adapter.mkdir       = (p)        => this.patchedMkdir(p);
    adapter.remove      = (p)        => this.patchedRemove(p);
    adapter.rename      = (p, np)    => this.patchedRename(p, np);
    adapter.copy        = (p, np)    => this.patchedCopy(p, np);
    adapter.trashSystem = (p)        => this.patchedTrashSystem(p);
    adapter.trashLocal  = (p)        => this.patchedTrashLocal(p);

    this.patched = true;
  }

  unpatch(adapter: IDataAdapter): void {
    if (!this.patched) return;

    const orig = this.originalMethods;
    if (orig.read)        adapter.read        = orig.read;
    if (orig.readBinary)  adapter.readBinary  = orig.readBinary;
    if (orig.write)       adapter.write       = orig.write;
    if (orig.writeBinary) adapter.writeBinary = orig.writeBinary;
    if (orig.append)      adapter.append      = orig.append;
    if (orig.process)     adapter.process     = orig.process;
    if (orig.exists)      adapter.exists      = orig.exists;
    if (orig.stat)        adapter.stat        = orig.stat;
    if (orig.list)        adapter.list        = orig.list;
    if (orig.mkdir)       adapter.mkdir       = orig.mkdir;
    if (orig.remove)      adapter.remove      = orig.remove;
    if (orig.rename)      adapter.rename      = orig.rename;
    if (orig.copy)        adapter.copy        = orig.copy;
    if (orig.trashSystem) adapter.trashSystem = orig.trashSystem;
    if (orig.trashLocal)  adapter.trashLocal  = orig.trashLocal;

    this.originalMethods = {};
    this.patched = false;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Публичные утилиты путей
  // ═══════════════════════════════════════════════════════════════════════

  /** normalizedPath → абсолютный путь в теневом хранилище (без .enc) */
  shadowAbs(normalizedPath: string): string {
    return nodePath.join(this.shadowRoot, ...normalizedPath.split("/"));
  }

  /** normalizedPath → абсолютный путь в оригинальном хранилище (без .enc) */
  originalAbs(normalizedPath: string): string {
    return nodePath.join(this.originalRoot, ...normalizedPath.split("/"));
  }

  /** normalizedPath → абсолютный путь к зашифрованному файлу в оригинальном хранилище (с .enc) */
  originalEncAbs(normalizedPath: string): string {
    return nodePath.join(this.originalRoot, ...normalizedPath.split("/")) + ENCRYPTED_EXT;
  }

  isBypassPath(normalizedPath: string): boolean {
    return (
      normalizedPath === "" ||
      normalizedPath === this.configDir ||
      normalizedPath.startsWith(this.configDir + "/")
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Миграция: шифрование существующих plaintext-файлов
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Возвращает true если в оригинальном хранилище есть незашифрованные файлы.
   * Это означает, что плагин устанавливается впервые на существующий vault.
   */
  async hasPendingMigration(): Promise<boolean> {
    const files = await this.scanPlaintextFiles();
    return files.length > 0;
  }

  /**
   * Шифрует все существующие plaintext-файлы в оригинальном хранилище.
   * file.md → file.md.enc  (оригинал удаляется после успешного шифрования).
   * Вызывается ОДИН РАЗ при первом запуске плагина или при обнаружении plaintext-файлов.
   */
  async encryptAllExisting(
    onProgress?: (done: number, total: number) => void
  ): Promise<void> {
    const plainFiles = await this.scanPlaintextFiles();
    let done = 0;

    console.debug(`[ShadowVault] Миграция: обнаружено ${plainFiles.length} незашифрованных файлов.`);

    for (const normalizedPath of plainFiles) {
      const origPath   = this.originalAbs(normalizedPath);
      const encPath    = this.originalEncAbs(normalizedPath);

      try {
        await fsp.mkdir(nodePath.dirname(encPath), { recursive: true });
        const stat = await fsp.stat(origPath);

        if (stat.size === 0) {
          // Пустой файл: создаём пустой .enc и удаляем оригинал
          await fsp.writeFile(encPath, Buffer.alloc(0));
        } else if (stat.size > 1024 * 1024) {
          // Большой файл: потоковое шифрование
          await this.engine.encryptStream(origPath, encPath);
        } else {
          // Маленький файл: буферное шифрование + атомарная запись
          const content   = await fsp.readFile(origPath);
          const encrypted = this.engine.encryptBuffer(content);
          await atomicWrite(encPath, encrypted);
        }

        // Удаляем оригинальный plaintext только после успешного шифрования
        await fsp.unlink(origPath);
        done++;
        onProgress?.(done, plainFiles.length);
        console.debug(`[ShadowVault] Зашифрован: "${normalizedPath}"`);
      } catch (err) {
        console.error(`[ShadowVault] Ошибка шифрования "${normalizedPath}":`, err);
        // Продолжаем с остальными файлами
      }
    }

    console.debug(`[ShadowVault] Миграция завершена: ${done}/${plainFiles.length}`);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Смена пароля: двухфазная атомарная пере-шифровка
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Пере-шифровывает все .enc файлы с новым ключом.
   *
   * Двухфазный алгоритм:
   *   Фаза 1 — создаём <file>.enc.new рядом с оригиналом (оригинал не трогаем).
   *            Если что-то пошло не так — удаляем все .enc.new и бросаем ошибку.
   *   Фаза 2 — переименовываем .enc.new → .enc (атомарно, по одному).
   *            После успешного переименования всех файлов оригинал заменён новым.
   *
   * Настройки (saltHex, verificationBlob) обновляются снаружи ПОСЛЕ успеха.
   */
  async reEncryptAll(
    newEngine: CryptoEngine,
    onProgress?: (done: number, total: number) => void
  ): Promise<void> {
    const encFiles = await this.scanEncryptedFiles();
    const total = encFiles.length;

    console.debug(`[ShadowVault] Пере-шифровка: ${total} файлов.`);

    // ── Фаза 1: создаём .enc.new ──────────────────────────────────────────
    const LARGE = 4 * 1024 * 1024; // 4 МБ

    for (let i = 0; i < total; i++) {
      const encPath    = this.originalEncAbs(encFiles[i]);
      const newEncPath = encPath + ".new";

      try {
        const stat = await fsp.stat(encPath);

        if (stat.size === 0) {
          await fsp.writeFile(newEncPath, Buffer.alloc(0));
        } else if (stat.size > LARGE) {
          // Потоковый подход для больших файлов чтобы не грузить RAM целиком
          const tmpDec = encPath + ".retmp";
          try {
            await this.engine.decryptStream(encPath, tmpDec);
            await newEngine.encryptStream(tmpDec, newEncPath);
          } finally {
            await fsp.unlink(tmpDec).catch(() => undefined);
          }
        } else {
          const encrypted = await fsp.readFile(encPath);
          const plain     = this.engine.decryptBuffer(encrypted);
          const reenc     = newEngine.encryptBuffer(plain);
          await fsp.writeFile(newEncPath, reenc);
        }

        onProgress?.(i + 1, total * 2);
      } catch (err) {
        // Откат: удаляем все созданные .enc.new
        for (let j = 0; j <= i; j++) {
          await fsp.unlink(this.originalEncAbs(encFiles[j]) + ".new").catch(() => undefined);
        }
        throw err;
      }
    }

    // ── Фаза 2: атомарная замена .enc.new → .enc ─────────────────────────
    for (let i = 0; i < total; i++) {
      const encPath = this.originalEncAbs(encFiles[i]);
      await fsp.rename(encPath + ".new", encPath);
      onProgress?.(total + i + 1, total * 2);
    }

    console.debug(`[ShadowVault] Пере-шифровка завершена: ${total} файлов.`);
  }

  /**
   * Сканирует оригинальное хранилище и возвращает normalizedPath
   * для всех зашифрованных файлов (.enc).
   */
  private async scanEncryptedFiles(relDir = ""): Promise<string[]> {
    const result: string[] = [];
    const absDir = relDir
      ? nodePath.join(this.originalRoot, ...relDir.split("/"))
      : this.originalRoot;

    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(absDir, { withFileTypes: true });
    } catch {
      return result;
    }

    const prefix = relDir ? relDir + "/" : "";
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      const rel = prefix + entry.name;
      if (entry.isDirectory()) {
        result.push(...await this.scanEncryptedFiles(rel));
      } else if (entry.isFile() && entry.name.endsWith(ENCRYPTED_EXT)) {
        result.push(rel.slice(0, -ENCRYPTED_EXT.length));
      }
    }
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Ядро: расшифровка по требованию (lazy decrypt)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Гарантирует наличие расшифрованного файла в теневом хранилище.
   * Источник истины — оригинальное хранилище (файлы .enc).
   */
  async ensureDecrypted(normalizedPath: string): Promise<void> {
    const shadowPath  = this.shadowAbs(normalizedPath);
    const origEncPath = this.originalEncAbs(normalizedPath);

    // Кэш-хит: файл уже в теневом хранилище
    if (await fileExists(shadowPath)) return;

    if (!(await fileExists(origEncPath))) {
      throw new Error(
        `[ShadowVault] Файл не найден в хранилище: "${normalizedPath}"`
      );
    }

    await fsp.mkdir(nodePath.dirname(shadowPath), { recursive: true });

    const stat = await fsp.stat(origEncPath);
    if (stat.size === 0) {
      await fsp.writeFile(shadowPath, Buffer.alloc(0));
      await fsp.utimes(shadowPath, stat.atime, stat.mtime);
      return;
    }

    // Потоковая расшифровка: origEncPath → shadowPath
    await this.engine.decryptStream(origEncPath, shadowPath);

    // Копируем mtime оригинала в shadow — критично для Crash Recovery:
    // только write-through файлы будут иметь shadow.mtime > original_enc.mtime
    const encStat = await fsp.stat(origEncPath);
    await fsp.utimes(shadowPath, encStat.atime, encStat.mtime);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Патченые методы адаптера
  // ═══════════════════════════════════════════════════════════════════════

  private async patchedRead(normalizedPath: string): Promise<string> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.read!(normalizedPath);
    }
    await this.ensureDecrypted(normalizedPath);
    return fsp.readFile(this.shadowAbs(normalizedPath), "utf8");
  }

  private async patchedReadBinary(normalizedPath: string): Promise<ArrayBuffer> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.readBinary!(normalizedPath);
    }
    await this.ensureDecrypted(normalizedPath);
    const buf = await fsp.readFile(this.shadowAbs(normalizedPath));
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }

  private async patchedWrite(
    normalizedPath: string,
    data: string,
    options?: DataWriteOptions
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.write!(normalizedPath, data, options);
    }

    const shadowPath  = this.shadowAbs(normalizedPath);
    const origEncPath = this.originalEncAbs(normalizedPath);

    await fsp.mkdir(nodePath.dirname(shadowPath),  { recursive: true });
    await fsp.mkdir(nodePath.dirname(origEncPath), { recursive: true });

    // 1. Открытый текст → теневое хранилище
    await fsp.writeFile(shadowPath, data, "utf8");

    // 2. Зашифровано → оригинальное хранилище (атомарно)
    const encrypted = this.engine.encryptBuffer(Buffer.from(data, "utf8"));
    await atomicWrite(origEncPath, encrypted);
  }

  private async patchedWriteBinary(
    normalizedPath: string,
    data: ArrayBuffer,
    options?: DataWriteOptions
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.writeBinary!(normalizedPath, data, options);
    }

    const shadowPath  = this.shadowAbs(normalizedPath);
    const origEncPath = this.originalEncAbs(normalizedPath);
    const buf = Buffer.from(data);

    await fsp.mkdir(nodePath.dirname(shadowPath),  { recursive: true });
    await fsp.mkdir(nodePath.dirname(origEncPath), { recursive: true });

    // Открытые байты → теневое хранилище
    await fsp.writeFile(shadowPath, buf);

    // Зашифровано → оригинальное хранилище
    if (buf.length > 1024 * 1024) {
      // > 1 МБ: потоковое шифрование shadow → origEnc
      // Временный файл encryptStream будет origEncPath + ".tmp" — отфильтрован из patchedList
      await this.engine.encryptStream(shadowPath, origEncPath);
    } else {
      const encrypted = this.engine.encryptBuffer(buf);
      await atomicWrite(origEncPath, encrypted);
    }
  }

  private async patchedAppend(
    normalizedPath: string,
    data: string,
    options?: DataWriteOptions
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.append!(normalizedPath, data, options);
    }

    const shadowPath  = this.shadowAbs(normalizedPath);
    const origEncPath = this.originalEncAbs(normalizedPath);

    if (await fileExists(origEncPath)) {
      await this.ensureDecrypted(normalizedPath);
    } else {
      await fsp.mkdir(nodePath.dirname(shadowPath), { recursive: true });
    }

    await fsp.appendFile(shadowPath, data, "utf8");

    const fullContent = await fsp.readFile(shadowPath, "utf8");
    const encrypted   = this.engine.encryptBuffer(Buffer.from(fullContent, "utf8"));
    await atomicWrite(origEncPath, encrypted);
  }

  private async patchedProcess(
    normalizedPath: string,
    fn: (data: string) => string,
    options?: DataWriteOptions
  ): Promise<string> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.process!(normalizedPath, fn, options);
    }
    await this.ensureDecrypted(normalizedPath);
    const current = await fsp.readFile(this.shadowAbs(normalizedPath), "utf8");
    const result = fn(current);
    await this.patchedWrite(normalizedPath, result, options);
    return result;
  }

  private async patchedExists(
    normalizedPath: string,
    sensitive?: boolean
  ): Promise<boolean> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.exists!(normalizedPath, sensitive);
    }
    // Файл существует если есть .enc в оригинале ИЛИ уже расшифрован в shadow
    return (
      (await fileExists(this.originalEncAbs(normalizedPath))) ||
      (await fileExists(this.shadowAbs(normalizedPath)))
    );
  }

  private async patchedStat(normalizedPath: string): Promise<AdapterStat | null> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.stat!(normalizedPath);
    }

    const shadowPath  = this.shadowAbs(normalizedPath);
    const origEncPath = this.originalEncAbs(normalizedPath);

    // Если файл уже расшифрован в теневом — возвращаем его стат (точный размер)
    const statPath = (await fileExists(shadowPath)) ? shadowPath : origEncPath;

    try {
      const s     = await fsp.stat(statPath);
      const isDir = s.isDirectory();
      // Вычитаем заголовок шифрования если читаем размер из .enc файла
      const size = (!isDir && statPath === origEncPath && s.size >= CRYPTO_HEADER_SIZE)
        ? s.size - CRYPTO_HEADER_SIZE
        : s.size;

      return {
        type:  isDir ? "folder" : "file",
        ctime: s.ctimeMs,
        mtime: s.mtimeMs,
        size,
      };
    } catch {
      return null;
    }
  }

  private async patchedList(normalizedPath: string): Promise<ListedFiles> {
    // "" (корень) НЕ байпасим — нам нужно перехватить список чтобы убрать .enc суффиксы.
    // .obsidian и его содержимое — байпасим (конфигурация Obsidian хранится незашифрованно).
    if (normalizedPath !== "" && this.isBypassPath(normalizedPath)) {
      return this.originalMethods.list!(normalizedPath);
    }

    // Источник истины: оригинальное хранилище (содержит .enc файлы)
    const absDir = this.originalAbs(normalizedPath);
    const files: string[] = [];
    const folders: string[] = [];

    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(absDir, { withFileTypes: true });
    } catch {
      return { files: [], folders: [] };
    }

    const prefix = normalizedPath ? normalizedPath + "/" : "";
    for (const entry of entries) {
      // Скрытые файлы (.session_active и т.п.) — не показываем Obsidian
      if (entry.name.startsWith(".") && entry.name !== this.configDir) continue;
      // Временные файлы атомарных операций
      if (isTempFile(entry.name)) continue;

      if (entry.isDirectory()) {
        folders.push(prefix + entry.name);
      } else if (entry.isFile() && entry.name.endsWith(ENCRYPTED_EXT)) {
        // Снимаем суффикс .enc — Obsidian видит обычные имена файлов
        const baseName = entry.name.slice(0, -ENCRYPTED_EXT.length);
        files.push(prefix + baseName);
      }
      // Не-.enc файлы в оригинальном хранилище не показываем:
      // они либо ещё не прошли миграцию (редко), либо системные файлы
    }

    return { files, folders };
  }

  private async patchedMkdir(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.mkdir!(normalizedPath);
    }
    await Promise.all([
      fsp.mkdir(this.shadowAbs(normalizedPath),   { recursive: true }),
      fsp.mkdir(this.originalAbs(normalizedPath), { recursive: true }),
    ]);
  }

  private async patchedRemove(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.remove!(normalizedPath);
    }
    await Promise.allSettled([
      fsp.unlink(this.shadowAbs(normalizedPath)),
      fsp.unlink(this.originalEncAbs(normalizedPath)),
    ]);
  }

  private async patchedRename(
    normalizedPath: string,
    newNormalizedPath: string
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.rename!(normalizedPath, newNormalizedPath);
    }

    const newShadow   = this.shadowAbs(newNormalizedPath);
    const newOrigEnc  = this.originalEncAbs(newNormalizedPath);

    await fsp.mkdir(nodePath.dirname(newShadow),  { recursive: true });
    await fsp.mkdir(nodePath.dirname(newOrigEnc), { recursive: true });

    const oldShadow = this.shadowAbs(normalizedPath);
    if (await fileExists(oldShadow)) {
      await fsp.rename(oldShadow, newShadow);
    }

    await fsp.rename(this.originalEncAbs(normalizedPath), newOrigEnc);
  }

  private async patchedCopy(
    normalizedPath: string,
    newNormalizedPath: string
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.copy!(normalizedPath, newNormalizedPath);
    }

    const newShadow  = this.shadowAbs(newNormalizedPath);
    const newOrigEnc = this.originalEncAbs(newNormalizedPath);

    await fsp.mkdir(nodePath.dirname(newShadow),  { recursive: true });
    await fsp.mkdir(nodePath.dirname(newOrigEnc), { recursive: true });

    const oldShadow = this.shadowAbs(normalizedPath);
    if (await fileExists(oldShadow)) {
      await fsp.copyFile(oldShadow, newShadow);
    }

    // Копия должна иметь свой IV → шифруем заново (нельзя просто копировать .enc блоб)
    await this.ensureDecrypted(normalizedPath);
    const content   = await fsp.readFile(this.shadowAbs(normalizedPath));
    const encrypted = this.engine.encryptBuffer(content);
    await atomicWrite(newOrigEnc, encrypted);
  }

  private async patchedTrashSystem(normalizedPath: string): Promise<boolean> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.trashSystem!(normalizedPath);
    }
    await fsp.unlink(this.shadowAbs(normalizedPath)).catch(() => undefined);
    try {
      await fsp.unlink(this.originalEncAbs(normalizedPath));
      return true;
    } catch {
      return false;
    }
  }

  private async patchedTrashLocal(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.trashLocal!(normalizedPath);
    }
    await fsp.unlink(this.shadowAbs(normalizedPath)).catch(() => undefined);
    await fsp.unlink(this.originalEncAbs(normalizedPath)).catch(() => undefined);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Вспомогательные методы
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Рекурсивно сканирует оригинальное хранилище и возвращает список
   * normalizedPath для файлов БЕЗ суффикса .enc (незашифрованных).
   * Нужен для обнаружения файлов, которые требуют первичной миграции.
   */
  private async scanPlaintextFiles(relDir = ""): Promise<string[]> {
    const result: string[] = [];
    const absDir = relDir
      ? nodePath.join(this.originalRoot, ...relDir.split("/"))
      : this.originalRoot;

    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(absDir, { withFileTypes: true });
    } catch {
      return result;
    }

    const prefix = relDir ? relDir + "/" : "";
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      // Пропускаем уже зашифрованные и временные файлы
      if (entry.name.endsWith(ENCRYPTED_EXT) || isTempFile(entry.name)) continue;

      const rel = prefix + entry.name;
      if (entry.isDirectory()) {
        const sub = await this.scanPlaintextFiles(rel);
        result.push(...sub);
      } else if (entry.isFile()) {
        result.push(rel);
      }
    }

    return result;
  }
}

