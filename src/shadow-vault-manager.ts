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
import { detectFormat, CHUNKED_HEADER_LENGTH, SEGMENT_LEN_PREFIX } from "./crypto/format";
import { IV_LENGTH, GCM_TAG_LENGTH } from "./crypto/constants";
import { migrateBuffer } from "./crypto/migration";
import { isBypassPath } from "./path-utils";
import type { LegacyVariant } from "./crypto/legacy";
import { IDataAdapter, AdapterStat, DataWriteOptions, ListedFiles } from "./adapter-types";
import {
  CRYPTO_HEADER_SIZE,
  ENCRYPTED_EXT,
  atomicWrite,
  ensureSymlink,
  fileExists,
  filesEqual,
  isTempFile,
  listEncryptedDir,
  parallelMap,
  removeSymlink,
  walkDir,
} from "./fs-utils";
import type { Logger } from "./logger";

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

  /** Опциональный структурный логгер (DI из main); тесты передают undefined. */
  private readonly logger?: Logger;

  constructor(engine: CryptoEngine, originalRoot: string, shadowRoot?: string, configDir = ".obsidian", logger?: Logger) {
    this.engine = engine;
    this.originalRoot = nodePath.normalize(originalRoot);
    this.configDir = configDir;
    this.logger = logger;

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
    if (this.mounted) {
      this.logger?.warn("shadow", "mount: уже примонтирован, пропускаем");
      return;
    }

    const adapterAny = adapter as unknown as { basePath?: string };

    this.originalBasePath = adapterAny.basePath ?? adapter.getBasePath();
    this.originalGetBasePath = adapter.getBasePath.bind(adapter);
    this.originalGetResourcePath = adapter.getResourcePath.bind(adapter);

    this.logger?.info("shadow", "mount", {
      from: this.originalBasePath,
      to: this.shadowRoot,
    });

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
    this.logger?.info("shadow", "unmount", {
      from: this.shadowRoot,
      to: this.originalBasePath,
    });

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

  /**
   * Полное удаление и пересоздание shadow vault.
   * Вызывается ПОСЛЕ recoverFromCrash: recovery записал актуальные правки
   * в original.enc, теперь shadow можно безопасно сбросить и заново
   * расшифровать с нуля — это гарантирует чистое состояние без stale-файлов.
   */
  async resetShadow(): Promise<void> {
    this.logger?.info("shadow", "resetShadow: rm", { path: this.shadowRoot });
    await fsp.rm(this.shadowRoot, { recursive: true, force: true });
    await fsp.mkdir(this.shadowRoot, { recursive: true });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Точечный мирроринг shadow → .enc через vault events
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Per-file mutex для encryptOne. Если для path уже идёт шифрование —
   * новый вызов цепляется в хвост promise-цепочки и ждёт. Защита от race:
   * Obsidian при autosave может стрельнуть modify несколько раз подряд,
   * параллельные encryptOne на одном пути приводили к torn writes в .enc.
   */
  private encryptLocks: Map<string, Promise<void>> = new Map();

  /**
   * Набор «в полёте» операций записи (write-through из vault-событий и
   * операции rename папок). Modify-обработчик в main.ts регистрирует сюда
   * каждый promise. drainPending() ждёт их завершения ПЕРЕД удалением shadow,
   * закрывая окно потери последней правки при закрытии Obsidian.
   */
  private pendingWrites: Set<Promise<unknown>> = new Set();

  /**
   * Регистрирует promise write-through в набор pendingWrites и
   * саморегистрирует его удаление по завершении (успех или ошибка).
   * Возвращает тот же promise для удобной цепочки в вызывающем коде.
   */
  trackPending<T>(p: Promise<T>): Promise<T> {
    this.pendingWrites.add(p);
    p.finally(() => this.pendingWrites.delete(p)).catch(() => undefined);
    return p;
  }

  /** Количество незавершённых write-through операций (для логов/тестов). */
  pendingCount(): number {
    return this.pendingWrites.size;
  }

  /**
   * Дренаж: ждёт завершения ВСЕХ in-flight write-through операций.
   * Делает несколько проходов, т.к. завершение одной операции может
   * породить новую (autosave-каскад). Возвращает после стабилизации
   * либо по достижении лимита проходов (защита от бесконечного цикла).
   */
  async drainPending(maxPasses = 50): Promise<void> {
    for (let pass = 0; pass < maxPasses; pass++) {
      if (this.pendingWrites.size === 0) {
        // Дополнительно убедимся, что и per-file очереди пусты.
        if (this.encryptLocks.size === 0) return;
      }
      const inflight = [
        ...this.pendingWrites,
        ...this.encryptLocks.values(),
      ];
      if (inflight.length === 0) return;
      await Promise.allSettled(inflight);
    }
    this.logger?.warn("shadow", "drainPending: лимит проходов исчерпан", {
      pending: this.pendingWrites.size,
      locks: this.encryptLocks.size,
    });
  }

  /**
   * Синхронная проверка: есть ли в shadow файлы новее своих .enc по mtime.
   * Грубая, но быстрая эвристика для onunload (где async недопустим): если
   * хотя бы один shadow-файл изменён позже .enc — значит есть несхороненные
   * правки, и shadow удалять НЕЛЬЗЯ (оставляем для crash recovery).
   *
   * Использует node fs sync напрямую (вызывается только на desktop).
   * Возвращает true, если найдены несхороненные изменения.
   */
  hasUnsyncedChangesSync(): boolean {
    const stack: string[] = [this.shadowRoot];
    while (stack.length > 0) {
      const dir = stack.pop()!;
      let entries: import("fs").Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        if (e.name === this.configDir || e.name.startsWith(".") || isTempFile(e.name)) {
          continue;
        }
        const abs = nodePath.join(dir, e.name);
        if (e.isDirectory()) {
          stack.push(abs);
          continue;
        }
        if (!e.isFile()) continue;
        const rel = nodePath.relative(this.shadowRoot, abs).split(nodePath.sep).join("/");
        const encAbs = this.originalEncAbs(rel);
        try {
          const sStat = fs.statSync(abs);
          let eStat: import("fs").Stats;
          try {
            eStat = fs.statSync(encAbs);
          } catch {
            // .enc нет вовсе — файл создан в shadow и не зашифрован → несхороненное
            return true;
          }
          // mtime shadow заметно новее .enc → правка не дошифрована.
          // Допуск 1с компенсирует разрешение mtime ФС и порядок записи.
          if (sStat.mtimeMs > eStat.mtimeMs + 1000) {
            return true;
          }
        } catch {
          continue;
        }
      }
    }
    return false;
  }

  /**
   * Синхронная финальная дошифровка несхороненных изменений (для onunload,
   * где async недопустим). Проходит shadow, для каждого файла новее своего
   * .enc (или без .enc) шифрует синхронно через engine.encryptBuffer и пишет
   * .enc атомарно (tmp + renameSync).
   *
   * ВАЖНО: цельным форматом v2 (sync-стрима у node:crypto нет). Для очень
   * больших файлов это разовая нагрузка при закрытии, но гарантирует, что
   * последняя правка попадёт в .enc до удаления shadow. Возвращает количество
   * дошифрованных и список не удавшихся (чтобы вызывающий НЕ удалял shadow).
   */
  encryptUnsyncedChangesSync(): { encrypted: number; failed: string[] } {
    let encrypted = 0;
    const failed: string[] = [];
    const stack: string[] = [this.shadowRoot];

    while (stack.length > 0) {
      const dir = stack.pop()!;
      let entries: import("fs").Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        if (e.name === this.configDir || e.name.startsWith(".") || isTempFile(e.name)) {
          continue;
        }
        const abs = nodePath.join(dir, e.name);
        if (e.isDirectory()) {
          stack.push(abs);
          continue;
        }
        if (!e.isFile()) continue;
        const rel = nodePath.relative(this.shadowRoot, abs).split(nodePath.sep).join("/");
        const encAbs = this.originalEncAbs(rel);

        // Нужно ли дошифровывать? Нет .enc → да. Иначе по mtime.
        let needs = false;
        let sStat: import("fs").Stats;
        try {
          sStat = fs.statSync(abs);
        } catch {
          continue;
        }
        try {
          const eStat = fs.statSync(encAbs);
          needs = sStat.mtimeMs > eStat.mtimeMs + 1000;
        } catch {
          needs = true; // .enc отсутствует
        }
        if (!needs) continue;

        try {
          fs.mkdirSync(nodePath.dirname(encAbs), { recursive: true });
          const enc =
            sStat.size === 0
              ? this.engine.encryptBuffer(Buffer.alloc(0)) // валидный v2, не 0 байт
              : this.engine.encryptBuffer(fs.readFileSync(abs));
          const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
          const tmp = `${encAbs}.${unique}.shadowtmp`;
          fs.writeFileSync(tmp, enc);
          fs.renameSync(tmp, encAbs);
          encrypted++;
        } catch (err) {
          this.logger?.error("shadow", "sync encrypt-back не удался", {
            path: rel,
            error: err instanceof Error ? err.message : String(err),
          });
          failed.push(rel);
        }
      }
    }
    return { encrypted, failed };
  }

  /**
   * Шифрует один файл из shadow в оригинал .enc.
   * Вызывается из vault.on("create" | "modify") в main.ts.
   *
   * Атомарно: пишет .enc.<unique>.shadowtmp, потом rename → .enc.
   * Per-file сериализация через encryptLocks — гарантирует что два
   * последовательных save'а на одном файле обработаются строго по порядку.
   */
  async encryptOne(normalizedPath: string): Promise<void> {
    const previous = this.encryptLocks.get(normalizedPath) ?? Promise.resolve();
    const next = previous.then(
      () => this.encryptOneInner(normalizedPath),
      () => this.encryptOneInner(normalizedPath) // даже если предыдущий упал, шифруем
    );
    this.encryptLocks.set(normalizedPath, next);
    try {
      await next;
    } finally {
      // Удаляем себя из карты только если никто не встал в очередь после нас
      if (this.encryptLocks.get(normalizedPath) === next) {
        this.encryptLocks.delete(normalizedPath);
      }
    }
  }

  private async encryptOneInner(normalizedPath: string): Promise<void> {
    const shadowAbs = this.shadowAbs(normalizedPath);
    const encAbs = this.originalEncAbs(normalizedPath);

    if (!(await fileExists(shadowAbs))) {
      this.logger?.warn("shadow", "encryptOne: нет файла в shadow, пропускаем", { path: normalizedPath });
      return;
    }

    await fsp.mkdir(nodePath.dirname(encAbs), { recursive: true });
    const stat = await fsp.stat(shadowAbs);

    if (stat.size === 0) {
      // Пустой по содержимому файл шифруем в ВАЛИДНЫЙ v2-контейнер (~33 байта:
      // MAGIC+ver+IV+tag), а НЕ в 0 байт. 0-байтный .enc — артефакт-аномалия,
      // который ломал детект формата (см. hasLegacyFiles/probe).
      await atomicWrite(encAbs, this.engine.encryptBuffer(Buffer.alloc(0)));
    } else if (stat.size > 4 * 1024 * 1024) {
      // encryptStream сам пишет в encAbs + ".tmp" + rename, своя атомарность
      await this.engine.encryptStream(shadowAbs, encAbs);
    } else {
      const buf = await fsp.readFile(shadowAbs);
      const enc = this.engine.encryptBuffer(buf);
      await atomicWrite(encAbs, enc);
    }

    this.logger?.debug("shadow", "encryptOne → .enc", { path: normalizedPath, bytes: stat.size });
  }

  /** Удаляет .enc файл в оригинале (вызывается из vault.on("delete")) */
  async unlinkEnc(normalizedPath: string): Promise<void> {
    const encAbs = this.originalEncAbs(normalizedPath);
    try {
      await fsp.unlink(encAbs);
      this.logger?.debug("shadow", "unlinkEnc", { path: normalizedPath });
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") {
        this.logger?.error("shadow", "unlinkEnc не удался", {
          path: normalizedPath,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  /** Переименование .enc файла (вызывается из vault.on("rename")) */
  async renameEnc(oldPath: string, newPath: string): Promise<void> {
    const oldEnc = this.originalEncAbs(oldPath);
    const newEnc = this.originalEncAbs(newPath);

    await fsp.mkdir(nodePath.dirname(newEnc), { recursive: true });

    if (await fileExists(oldEnc)) {
      await fsp.rename(oldEnc, newEnc);
      this.logger?.debug("shadow", "renameEnc", { from: oldPath, to: newPath });
    } else {
      // Старого .enc нет (мог не успеть зашифроваться) — шифруем новый
      this.logger?.warn("shadow", "renameEnc: oldEnc не найден, шифруем новый из shadow", { path: oldEnc });
      await this.encryptOne(newPath);
    }
  }

  /** Создаёт пустую папку в оригинале (зеркалирует mkdir в shadow) */
  async mkdirOriginal(normalizedPath: string): Promise<void> {
    const orig = this.originalAbs(normalizedPath);
    await fsp.mkdir(orig, { recursive: true });
    this.logger?.debug("shadow", "mkdirOriginal", { path: normalizedPath });
  }

  /** Удаляет пустую папку в оригинале (зеркалирует rmdir в shadow) */
  async rmdirOriginal(normalizedPath: string): Promise<void> {
    const orig = this.originalAbs(normalizedPath);
    try {
      await fsp.rmdir(orig);
      this.logger?.debug("shadow", "rmdirOriginal", { path: normalizedPath });
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      // ENOTEMPTY → папка не пуста (Obsidian мог удалить только часть детей).
      // ENOENT → уже удалена. Оба — ок.
      if (code !== "ENOENT" && code !== "ENOTEMPTY") {
        this.logger?.error("shadow", "rmdirOriginal не удался", {
          path: normalizedPath,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
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
    // Сначала зеркалим всю структуру папок (включая пустые) из оригинала в shadow.
    // Иначе при попытке создать заметку в пустой папке Obsidian native fs.writeFile
    // получит ENOENT — папки в shadow нет, хотя в дереве она отображается
    // (vault.fileMap её знает по первичному скану через patchListEarly).
    const folders = await this.replicateFolderStructure();
    this.logger?.info("shadow", "зеркало папок original → shadow", { folders });

    const encFiles = await this.scanEncryptedFiles();
    const decrypted: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];
    const concurrency = bulkConcurrency();

    this.logger?.info("shadow", "bulk decrypt", {
      files: encFiles.length,
      from: this.originalRoot,
      to: this.shadowRoot,
      concurrency,
    });

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
          this.logger?.error("shadow", "decryptAllToShadow: файл не расшифрован", {
            path: normalizedPath,
            error: msg,
          });
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
    this.logger?.debug("shadow", "bulk decrypt завершён", {
      ok: decrypted.length,
      failed: failed.length,
    });
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
    this.logger?.debug("shadow", "encrypt-back", { files: shadowFiles.length, concurrency });

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
          this.logger?.error("shadow", "encrypt-back: файл не зашифрован", {
            path: normalizedPath,
            error: msg,
          });
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
    this.logger?.debug("shadow", "encrypt-back завершён", {
      encrypted: encrypted.length,
      failed: failed.length,
    });
    return { encrypted, failed };
  }

  /**
   * Экспорт plaintext из shadow в оригинал и удаление всех .enc файлов.
   * Используется при отключении шифрования — после этого vault содержит
   * открытые файлы, плагин переходит в спящий режим.
   *
   * БЕЗОПАСНАЯ ДВУХФАЗНАЯ СХЕМА (защита от смешанного состояния при сбое):
   *   ФАЗА 1 — экспорт+verify ВСЕХ файлов:
   *     каждый shadow-файл пишется в оригинал атомарно (tmp + rename) и
   *     ПОБАЙТОВО сверяется с источником. .enc при этом НЕ трогаются.
   *     Если хоть один файл не удался — операция прерывается, возвращается
   *     failed[], и НИ ОДИН .enc не удаляется (plaintext появился рядом с
   *     ещё живым .enc — повторный вызов идемпотентно перезапишет plaintext
   *     и в этот раз сможет удалить .enc).
   *   ФАЗА 2 — удаление .enc батчем В КОНЦЕ:
   *     только если ВСЕ экспорты прошли, удаляем .enc файлы — но СТРОГО те,
   *     чей plaintext был экспортирован в фазе 1. Orphan .enc (есть в
   *     оригинале, но не было в shadow — например не расшифровались при
   *     unlock из-за повреждения или чужого ключа) НЕ удаляются: их plaintext
   *     не экспортирован, и .enc — единственная копия данных. Они возвращаются
   *     в skippedOrphans, чтобы вызывающий предупредил пользователя.
   *     Сбой здесь не теряет данные: plaintext уже на месте и проверен,
   *     а повторный вызов до-удалит оставшиеся .enc.
   *
   * Идемпотентность: повторный вызов после частичного успеха безопасен —
   * фаза 1 перезапишет plaintext (verify пройдёт), фаза 2 удалит .enc.
   */
  async exportShadowToOriginal(
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<{
    exported: string[];
    failed: Array<{ path: string; error: string }>;
    skippedOrphans: string[];
  }> {
    const exported: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];
    const skippedOrphans: string[] = [];

    const shadowFiles = await this.scanShadowFilesForSync();
    const total = shadowFiles.length;
    this.logger?.info("shadow", "export shadow→original (фаза 1: экспорт+verify)", { files: total });

    // ── ФАЗА 1: экспортируем и верифицируем ВСЕ файлы, .enc не трогаем ──
    for (let i = 0; i < total; i++) {
      const rel = shadowFiles[i];
      try {
        const src = this.shadowAbs(rel);
        const dst = this.originalAbs(rel);
        await fsp.mkdir(nodePath.dirname(dst), { recursive: true });

        // Атомарная запись plaintext: tmp + rename, чтобы сбой посреди копии
        // не оставил усечённый/повреждённый оригинал.
        const buf = await fsp.readFile(src);
        await atomicWrite(dst, buf);

        // Verify: побайтовая сверка записанного оригинала с источником.
        const ok = await filesEqual(src, dst);
        if (!ok) {
          throw new Error("verify не прошёл: записанный plaintext не совпал с shadow");
        }

        exported.push(rel);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger?.error("shadow", "export файла не удался", { path: rel, error: msg });
        failed.push({ path: rel, error: msg });
      }
      onProgress?.(i + 1, total, rel);
    }

    // Если хоть один файл не экспортировался/не верифицировался — НЕ удаляем
    // .enc. Возвращаем failed: вызывающий (disableEncryption) откатится с
    // понятной ошибкой, .enc нетронуты, plaintext не потерян.
    if (failed.length > 0) {
      this.logger?.error("shadow", "export: часть файлов не удалась — .enc НЕ удаляем, шифрование остаётся включённым", {
        failed: failed.length,
      });
      return { exported, failed, skippedOrphans };
    }

    // ── ФАЗА 2: все экспорты успешны → удаляем .enc батчем в конце ──
    this.logger?.info("shadow", "export фаза 2: удаление .enc", { exported: exported.length });
    // Удаляем СТРОГО те .enc, чей plaintext экспортирован в фазе 1.
    // Orphan .enc (есть в оригинале, но не было в shadow — например не
    // расшифровались при unlock: повреждены или зашифрованы другим ключом)
    // НЕ трогаем: их plaintext не экспортирован, .enc — единственная копия.
    const encToRemove = new Set<string>(exported);
    for (const rel of await this.scanEncryptedFiles()) {
      if (!encToRemove.has(rel)) skippedOrphans.push(rel);
    }
    if (skippedOrphans.length > 0) {
      this.logger?.warn("shadow", "export: orphan .enc без экспортированного plaintext — оставлены на диске", {
        count: skippedOrphans.length,
        files: skippedOrphans,
      });
    }

    for (const rel of encToRemove) {
      try {
        await fsp.unlink(this.originalEncAbs(rel));
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== "ENOENT") {
          // Удаление .enc не удалось, но plaintext уже на месте и проверен —
          // данные не потеряны. Логируем; повторный disableEncryption до-удалит.
          this.logger?.error("shadow", "export: не удалось удалить .enc", {
            path: rel,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }

    this.logger?.info("shadow", "export завершён", {
      files: exported.length,
      errors: failed.length,
      skippedOrphans: skippedOrphans.length,
    });
    return { exported, failed, skippedOrphans };
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
    // ЕДИНЫЙ КОНТРАКТ ПУСТЫХ ФАЙЛОВ: пустой plaintext ВСЕГДА шифруется в
    // валидный v2-контейнер (~33 байта), а НЕ в 0 байт. Так детект формата и
    // все читающие пути работают единообразно.
    const stat = await fsp.stat(shadowAbsPath);
    if (stat.size === 0) {
      const enc = this.engine.encryptBuffer(Buffer.alloc(0));
      await fsp.writeFile(encNewPath, enc);
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
        // .enc.new — валидный v2-контейнер пустого plaintext; проверяем что
        // он расшифровывается в пустоту.
        await this.engine.decryptStream(encNewPath, verifyTmpPath);
        const ok = await filesEqual(shadowAbsPath, verifyTmpPath);
        if (!ok) {
          throw new Error("Verify failed: decrypt(.enc.new) != shadow (пустой файл)");
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
  private async scanShadowFilesForSync(): Promise<string[]> {
    const result: string[] = [];
    await walkDir(this.shadowRoot, (e) => {
      // .obsidian — symlink на оригинал; скрытые/служебные; временные — пропуск
      if (e.name === this.configDir || e.name.startsWith(".") || isTempFile(e.name)) {
        return "skip";
      }
      if (e.isFile) result.push(e.rel);
      return "recurse";
    });
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

  /** Возвращает активный v2-движок (для создания verificationBlob после миграции). */
  getEngine(): CryptoEngine {
    return this.engine;
  }

  isBypassPath(normalizedPath: string): boolean {
    return isBypassPath(normalizedPath, this.configDir);
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

    this.logger?.debug("shadow", "миграция: обнаружены незашифрованные файлы", { files: plainFiles.length });

    for (const normalizedPath of plainFiles) {
      const origPath   = this.originalAbs(normalizedPath);
      const encPath    = this.originalEncAbs(normalizedPath);

      try {
        await fsp.mkdir(nodePath.dirname(encPath), { recursive: true });
        const stat = await fsp.stat(origPath);

        if (stat.size === 0) {
          // Пустой файл: шифруем в валидный v2-контейнер (не 0 байт).
          await atomicWrite(encPath, this.engine.encryptBuffer(Buffer.alloc(0)));
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
        this.logger?.debug("shadow", "зашифрован", { path: normalizedPath });
      } catch (err) {
        this.logger?.error("shadow", "ошибка шифрования файла", {
          path: normalizedPath,
          error: err instanceof Error ? err.message : String(err),
        });
        // Продолжаем с остальными файлами
      }
    }

    this.logger?.debug("shadow", "миграция завершена", { done, total: plainFiles.length });
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
   * Настройки (verificationBlob) обновляются снаружи ПОСЛЕ успеха.
   */
  async reEncryptAll(
    newEngine: CryptoEngine,
    onProgress?: (done: number, total: number) => void
  ): Promise<void> {
    const encFiles = await this.scanEncryptedFiles();
    const total = encFiles.length;

    this.logger?.debug("shadow", "пере-шифровка: старт", { files: total });

    // ── Фаза 1: создаём .enc.new ──────────────────────────────────────────
    const LARGE = 4 * 1024 * 1024; // 4 МБ

    for (let i = 0; i < total; i++) {
      const encPath    = this.originalEncAbs(encFiles[i]);
      const newEncPath = encPath + ".new";

      try {
        const stat = await fsp.stat(encPath);

        if (stat.size === 0) {
          // Legacy 0-байтный .enc трактуем как пустой plaintext и пере-шифруем
          // в ВАЛИДНЫЙ v2-контейнер новым ключом (единый контракт пустых файлов).
          await fsp.writeFile(newEncPath, newEngine.encryptBuffer(Buffer.alloc(0)));
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

    this.logger?.debug("shadow", "пере-шифровка завершена", { files: total });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ФАЗА 4: миграция старого формата (legacy) → v2
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Возвращает true, если в оригинальном хранилище есть хотя бы один .enc
   * НЕ в формате v2 (legacy) → требуется миграция. Детект по MAGIC дешёвый:
   * читаем только первые байты заголовка каждого файла.
   */
  async hasLegacyFiles(): Promise<boolean> {
    const encFiles = await this.scanEncryptedFiles();
    for (const p of encFiles) {
      const head = await this.readEncHead(this.originalEncAbs(p));
      if (!head) continue;
      const fmt = detectFormat(head);
      // Legacy определяем ТОЛЬКО позитивно. "v2"/"v2-chunked" — новый формат;
      // "unknown" (пустой 0-байтный или слишком короткий/битый .enc) НЕ legacy
      // и не должен заставлять плагин запускать миграцию.
      if (fmt === "legacy-node" || fmt === "legacy-web") return true;
      if (fmt === "unknown" && head.length > 0) {
        this.logger?.warn("shadow", "подозрительный .enc (нераспознан)", {
          path: p,
          headBytes: head.length,
        });
      }
    }
    return false;
  }

  /** Читает заголовок .enc (первые HEADER_SIZE байт) для детекта формата. */
  private async readEncHead(absPath: string): Promise<Uint8Array | null> {
    try {
      const fh = await fsp.open(absPath, "r");
      try {
        // 33 байта = MAGIC(4)+ver(1)+IV(12)+tag(16) — хватает и для detectFormat,
        // и для отсечения слишком коротких/пустых файлов.
        const buf = Buffer.alloc(CRYPTO_HEADER_SIZE);
        const { bytesRead } = await fh.read(buf, 0, CRYPTO_HEADER_SIZE, 0);
        return buf.subarray(0, bytesRead);
      } finally {
        await fh.close();
      }
    } catch {
      return null;
    }
  }

  /** Читает .enc целиком по normalizedPath (для probe/диагностики). */
  async readEncFull(normalizedPath: string): Promise<Buffer> {
    return fsp.readFile(this.originalEncAbs(normalizedPath));
  }

  /**
   * Самовосстановление блоба для v2-хранилища без verificationBlob (desktop).
   * Пытается расшифровать первый ВАЛИДНЫЙ v2/v2-chunked .enc текущим движком
   * (ключ выведен из email+password). Успех → пароль верный, провал (GCM auth)
   * → неверный. Пустые (0 байт)/legacy/битые .enc пропускаются.
   *
   * @returns true — пароль верный; false — неверный; null — валидных v2 нет
   *          (пустое/новое хранилище — нечего проверять).
   */
  async validateV2Password(): Promise<boolean | null> {
    const encFiles = await this.scanEncryptedFiles();
    for (const p of encFiles) {
      const abs = this.originalEncAbs(p);
      let buf: Buffer;
      try {
        buf = await fsp.readFile(abs);
      } catch {
        continue; // нечитаемый — к следующему
      }
      const fmt = detectFormat(new Uint8Array(buf));
      if (fmt !== "v2" && fmt !== "v2-chunked") continue; // пропускаем пустые/legacy/битые
      try {
        // Для v2-chunked буферный decryptBuffer тоже валиден (читает заголовок 0x03).
        this.engine.decryptBuffer(buf);
        return true; // расшифровалось → пароль верный
      } catch {
        return false; // GCM auth fail → неверный пароль
      }
    }
    return null; // валидных v2-файлов нет
  }

  /**
   * Мигрирует все legacy .enc файлы в формат v2.
   *
   * Атомарность ПОФАЙЛОВО:
   *   legacy.enc → читаем → migrateBuffer (legacy-decrypt старым ключом,
   *   re-encrypt новым v2-ключом, round-trip verify в памяти) → atomicWrite
   *   в .enc.new → rename .new → .enc. Файл никогда не остаётся полу-мигрированным.
   *
   * Идемпотентность: уже-v2 файлы пропускаются (migrateBuffer вернёт skipped-v2).
   * Прерванный прогон корректно домигрирует остаток при повторном запуске.
   *
   * Безопасность: если round-trip verify не прошёл или legacy-decrypt упал —
   * файл помечается failed, оригинал НЕ трогается, миграция продолжается дальше.
   *
   * @param password пароль для деривации СТАРОГО legacy-ключа (тот же, что ввёл
   *                 пользователь; v2-движок this.engine уже несёт новый ключ)
   */
  async migrateLegacyToV2(
    password: string,
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<{ migrated: string[]; skipped: number; failed: Array<{ path: string; error: string }> }> {
    const encFiles = await this.scanEncryptedFiles();
    const migrated: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];
    let skipped = 0;
    let done = 0;
    // hint: первый успешный legacy-вариант обычно общий для всего хранилища.
    let hint: LegacyVariant | undefined;

    this.logger?.info("shadow", "миграция legacy → v2: старт", { files: encFiles.length });

    for (const normalizedPath of encFiles) {
      const encPath    = this.originalEncAbs(normalizedPath);
      const newEncPath = encPath + ".new";
      try {
        const enc = new Uint8Array(await fsp.readFile(encPath));
        const res = await migrateBuffer(enc, password, this.engine, hint);

        if (res.status === "skipped-v2") {
          skipped++;
        } else {
          hint = res.variant;
          // Атомарная замена: пишем .new, затем rename поверх legacy.
          await atomicWrite(newEncPath, Buffer.from(res.v2));
          await fsp.rename(newEncPath, encPath);
          migrated.push(normalizedPath);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger?.error("shadow", "миграция файла не удалась", { path: normalizedPath, error: msg });
        failed.push({ path: normalizedPath, error: msg });
        // Подчищаем возможный недописанный .new (atomicWrite уже чистит свой tmp,
        // но rename мог не успеть — удаляем .new если остался).
        await fsp.unlink(newEncPath).catch(() => undefined);
      }
      done++;
      onProgress?.(done, encFiles.length, normalizedPath);
    }

    this.logger?.info("shadow", "миграция legacy → v2 завершена", {
      migrated: migrated.length,
      skipped,
      failed: failed.length,
    });
    return { migrated, skipped, failed };
  }

  /**
   * Зеркалит структуру папок original → shadow рекурсивно.
   * Включая пустые папки — иначе пользователь не сможет создать в них
   * новую заметку (Obsidian упадёт с ENOENT при native writeFile).
   *
   * Пропускает: dotfiles (включая configDir — для него отдельный symlink).
   * Возвращает количество созданных директорий (для прогресс-логов).
   */
  private async replicateFolderStructure(): Promise<number> {
    let count = 0;
    const mkdirs: Promise<unknown>[] = [];
    await walkDir(this.originalRoot, (e) => {
      if (e.name.startsWith(".") || !e.isDirectory) return "skip";
      const shadowDirAbs = nodePath.join(this.shadowRoot, ...e.rel.split("/"));
      mkdirs.push(fsp.mkdir(shadowDirAbs, { recursive: true }));
      count++;
      // Рекурсивно — не теряем глубоко вложенные пустые папки
      return "recurse";
    });
    await Promise.all(mkdirs);
    return count;
  }

  /**
   * Сканирует оригинальное хранилище и возвращает normalizedPath
   * для всех зашифрованных файлов (.enc).
   */
  async scanEncryptedFiles(): Promise<string[]> {
    const result: string[] = [];
    await walkDir(this.originalRoot, (e) => {
      if (e.name.startsWith(".")) return "skip";
      if (e.isFile && e.name.endsWith(ENCRYPTED_EXT)) {
        result.push(e.rel.slice(0, -ENCRYPTED_EXT.length));
      }
      return "recurse";
    });
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
      this.logger?.debug("shadow", "write: bypass", { path: normalizedPath });
      return this.originalMethods.write!(normalizedPath, data, options);
    }

    const shadowPath  = this.shadowAbs(normalizedPath);
    const origEncPath = this.originalEncAbs(normalizedPath);

    this.logger?.debug("shadow", "write → shadow + .enc", { path: normalizedPath, chars: data.length });

    await fsp.mkdir(nodePath.dirname(shadowPath),  { recursive: true });
    await fsp.mkdir(nodePath.dirname(origEncPath), { recursive: true });

    // 1. СНАЧАЛА шифруем в память. Если шифрование падает — НЕ трогаем shadow,
    //    пробрасываем ошибку (Obsidian узнает о неуспехе записи), и .enc/shadow
    //    остаются в прежнем согласованном состоянии.
    const encrypted = this.engine.encryptBuffer(Buffer.from(data, "utf8"));

    // 2. Только при успешном шифровании пишем И shadow, И .enc (атомарно).
    await fsp.writeFile(shadowPath, data, "utf8");
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

    // Зашифровано → оригинальное хранилище
    if (buf.length > 1024 * 1024) {
      // > 1 МБ: потоковое шифрование shadow → origEnc (читает из shadow,
      // поэтому shadow пишем первым). Своя атомарность через .tmp + rename.
      await fsp.writeFile(shadowPath, buf);
      await this.engine.encryptStream(shadowPath, origEncPath);
    } else {
      // Малый файл: СНАЧАЛА шифруем в память; при ошибке shadow не трогаем
      // (как в patchedWrite — без рассинхрона shadow/.enc).
      const encrypted = this.engine.encryptBuffer(buf);
      await fsp.writeFile(shadowPath, buf);
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

  /**
   * Вычисляет размер plaintext по .enc-файлу БЕЗ полной расшифровки.
   *   - v2 (0x02): plaintext = размер_файла − CRYPTO_HEADER_SIZE (33).
   *   - v2-chunked (0x03): читаем только префиксы длин сегментов и суммируем
   *     plaintext-длины: Σ(segLen − IV − tag). Файл целиком не читаем.
   *   - 0 байт (legacy-артефакт пустого файла): plaintext = 0.
   *   - прочее/нераспознанное: грубо не искажаем — отдаём размер файла как есть.
   * @param encAbs абсолютный путь к .enc
   * @param fileSize размер .enc из stat (чтобы не делать повторный stat)
   */
  private async plaintextSizeOfEnc(encAbs: string, fileSize: number): Promise<number> {
    if (fileSize === 0) return 0;

    let fh: import("fs/promises").FileHandle;
    try {
      fh = await fsp.open(encAbs, "r");
    } catch {
      return fileSize;
    }
    try {
      // Читаем заголовок для детекта формата.
      const head = Buffer.alloc(CHUNKED_HEADER_LENGTH);
      const { bytesRead } = await fh.read(head, 0, CHUNKED_HEADER_LENGTH, 0);
      const fmt = detectFormat(head.subarray(0, bytesRead));

      if (fmt === "v2") {
        // Цельный контейнер: фиксированный overhead 33 байта.
        return fileSize >= CRYPTO_HEADER_SIZE ? fileSize - CRYPTO_HEADER_SIZE : fileSize;
      }

      if (fmt === "v2-chunked") {
        // Суммируем plaintext-длины сегментов по их u32-префиксам, читая
        // только 4 байта на сегмент (тело файла не читаем).
        const SEG_OVERHEAD = IV_LENGTH + GCM_TAG_LENGTH; // IV + GCM-tag на сегмент
        let off = CHUNKED_HEADER_LENGTH;
        let plaintext = 0;
        const lenBuf = Buffer.alloc(SEGMENT_LEN_PREFIX);
        for (;;) {
          if (off + SEGMENT_LEN_PREFIX > fileSize) break;
          const r = await fh.read(lenBuf, 0, SEGMENT_LEN_PREFIX, off);
          if (r.bytesRead < SEGMENT_LEN_PREFIX) break;
          const segLen =
            (lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24)) >>> 0;
          if (segLen < SEG_OVERHEAD) break; // защита от битого заголовка
          plaintext += segLen - SEG_OVERHEAD;
          off += SEGMENT_LEN_PREFIX + segLen;
        }
        return plaintext;
      }

      // legacy/unknown — точного overhead не знаем; не искажаем грубо.
      return fileSize;
    } catch {
      return fileSize;
    } finally {
      await fh.close().catch(() => undefined);
    }
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
      // Размер plaintext: для shadow — как есть; для .enc — компенсируем overhead
      // с учётом формата (v2 / v2-chunked), без грубого искажения для chunked.
      const size = (!isDir && statPath === origEncPath)
        ? await this.plaintextSizeOfEnc(origEncPath, s.size)
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

    // Источник истины: оригинальное хранилище (содержит .enc файлы).
    // Единый list-транслятор (см. fs-utils.listEncryptedDir).
    return listEncryptedDir(
      this.originalAbs(normalizedPath),
      normalizedPath,
      this.configDir
    );
  }

  private async patchedMkdir(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      this.logger?.debug("shadow", "mkdir: bypass", { path: normalizedPath });
      return this.originalMethods.mkdir!(normalizedPath);
    }
    this.logger?.debug("shadow", "mkdir → shadow + original", { path: normalizedPath });
    await Promise.all([
      fsp.mkdir(this.shadowAbs(normalizedPath),   { recursive: true }),
      fsp.mkdir(this.originalAbs(normalizedPath), { recursive: true }),
    ]);
  }

  private async patchedRemove(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      this.logger?.debug("shadow", "remove: bypass", { path: normalizedPath });
      return this.originalMethods.remove!(normalizedPath);
    }
    this.logger?.debug("shadow", "remove → shadow + .enc", { path: normalizedPath });
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
      this.logger?.debug("shadow", "rename: bypass", { from: normalizedPath, to: newNormalizedPath });
      return this.originalMethods.rename!(normalizedPath, newNormalizedPath);
    }

    const newShadow   = this.shadowAbs(newNormalizedPath);
    const newOrigEnc  = this.originalEncAbs(newNormalizedPath);
    const oldShadow   = this.shadowAbs(normalizedPath);
    const oldOrigEnc  = this.originalEncAbs(normalizedPath);

    this.logger?.debug("shadow", "rename", { from: normalizedPath, to: newNormalizedPath });

    await fsp.mkdir(nodePath.dirname(newShadow),  { recursive: true });
    await fsp.mkdir(nodePath.dirname(newOrigEnc), { recursive: true });

    const shadowExists = await fileExists(oldShadow);
    const encExists = await fileExists(oldOrigEnc);
    this.logger?.debug("shadow", "rename: проверка источников", { shadowExists, encExists });

    if (shadowExists) {
      await fsp.rename(oldShadow, newShadow);
    } else {
      this.logger?.warn("shadow", "rename: oldShadow НЕ НАЙДЕН — пропускаем shadow rename", { path: oldShadow });
    }

    if (encExists) {
      await fsp.rename(oldOrigEnc, newOrigEnc);
    } else {
      this.logger?.warn("shadow", "rename: oldEnc НЕ НАЙДЕН — пропускаем .enc rename", { path: oldOrigEnc });
    }
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

