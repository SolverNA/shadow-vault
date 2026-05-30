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
import { detectFormat } from "./crypto/format";
import { migrateBuffer } from "./crypto/migration";
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
    if (this.mounted) {
      console.warn("[ShadowVault] mount: уже примонтирован, пропускаем");
      return;
    }

    const adapterAny = adapter as unknown as { basePath?: string };

    this.originalBasePath = adapterAny.basePath ?? adapter.getBasePath();
    this.originalGetBasePath = adapter.getBasePath.bind(adapter);
    this.originalGetResourcePath = adapter.getResourcePath.bind(adapter);

    console.info(
      `[ShadowVault] mount: basePath ${this.originalBasePath} → ${this.shadowRoot}`
    );

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
    console.info(
      `[ShadowVault] unmount: basePath ${this.shadowRoot} → ${this.originalBasePath}`
    );

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
    console.info(`[ShadowVault] resetShadow: rm ${this.shadowRoot}`);
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
    console.warn(
      `[ShadowVault] drainPending: лимит проходов исчерпан, осталось ` +
      `${this.pendingWrites.size} pending / ${this.encryptLocks.size} locks`
    );
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
              ? Buffer.alloc(0)
              : this.engine.encryptBuffer(fs.readFileSync(abs));
          const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
          const tmp = `${encAbs}.${unique}.shadowtmp`;
          fs.writeFileSync(tmp, enc);
          fs.renameSync(tmp, encAbs);
          encrypted++;
        } catch (err) {
          console.error(`[ShadowVault] sync encrypt-back "${rel}":`, err);
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
      console.warn(`[ShadowVault:encryptOne] ${normalizedPath}: нет файла в shadow, пропускаем`);
      return;
    }

    await fsp.mkdir(nodePath.dirname(encAbs), { recursive: true });
    const stat = await fsp.stat(shadowAbs);

    if (stat.size === 0) {
      await atomicWrite(encAbs, Buffer.alloc(0));
    } else if (stat.size > 4 * 1024 * 1024) {
      // encryptStream сам пишет в encAbs + ".tmp" + rename, своя атомарность
      await this.engine.encryptStream(shadowAbs, encAbs);
    } else {
      const buf = await fsp.readFile(shadowAbs);
      const enc = this.engine.encryptBuffer(buf);
      await atomicWrite(encAbs, enc);
    }

    console.debug(`[ShadowVault:encryptOne] ${normalizedPath} → .enc (${stat.size}B)`);
  }

  /** Удаляет .enc файл в оригинале (вызывается из vault.on("delete")) */
  async unlinkEnc(normalizedPath: string): Promise<void> {
    const encAbs = this.originalEncAbs(normalizedPath);
    try {
      await fsp.unlink(encAbs);
      console.debug(`[ShadowVault:unlinkEnc] ${normalizedPath}`);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") {
        console.error(`[ShadowVault:unlinkEnc] ${normalizedPath}:`, err);
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
      console.debug(`[ShadowVault:renameEnc] ${oldPath} → ${newPath}`);
    } else {
      // Старого .enc нет (мог не успеть зашифроваться) — шифруем новый
      console.warn(`[ShadowVault:renameEnc] oldEnc ${oldEnc} не найден, шифруем новый из shadow`);
      await this.encryptOne(newPath);
    }
  }

  /** Создаёт пустую папку в оригинале (зеркалирует mkdir в shadow) */
  async mkdirOriginal(normalizedPath: string): Promise<void> {
    const orig = this.originalAbs(normalizedPath);
    await fsp.mkdir(orig, { recursive: true });
    console.debug(`[ShadowVault:mkdirOriginal] ${normalizedPath}`);
  }

  /** Удаляет пустую папку в оригинале (зеркалирует rmdir в shadow) */
  async rmdirOriginal(normalizedPath: string): Promise<void> {
    const orig = this.originalAbs(normalizedPath);
    try {
      await fsp.rmdir(orig);
      console.debug(`[ShadowVault:rmdirOriginal] ${normalizedPath}`);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      // ENOTEMPTY → папка не пуста (Obsidian мог удалить только часть детей).
      // ENOENT → уже удалена. Оба — ок.
      if (code !== "ENOENT" && code !== "ENOTEMPTY") {
        console.error(`[ShadowVault:rmdirOriginal] ${normalizedPath}:`, err);
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
    console.info(`[ShadowVault] Зеркало папок: ${folders} директорий из original → shadow`);

    const encFiles = await this.scanEncryptedFiles();
    const decrypted: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];
    const concurrency = bulkConcurrency();

    console.info(
      `[ShadowVault] Bulk decrypt: ${encFiles.length} файлов из ${this.originalRoot} → ${this.shadowRoot}, ` +
      `concurrency=${concurrency}`
    );
    if (encFiles.length > 0 && encFiles.length <= 50) {
      console.debug("[ShadowVault] Файлы для decrypt:", encFiles);
    }

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
   *     только если ВСЕ экспорты прошли, удаляем .enc файлы (включая orphan,
   *     которых не было в shadow). Сбой здесь не теряет данные: plaintext уже
   *     на месте и проверен, а повторный вызов до-удалит оставшиеся .enc.
   *
   * Идемпотентность: повторный вызов после частичного успеха безопасен —
   * фаза 1 перезапишет plaintext (verify пройдёт), фаза 2 удалит .enc.
   */
  async exportShadowToOriginal(
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<{ exported: string[]; failed: Array<{ path: string; error: string }> }> {
    const exported: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];

    const shadowFiles = await this.scanShadowFilesForSync();
    const total = shadowFiles.length;
    console.info(`[ShadowVault] export shadow→original: ${total} файлов (фаза 1: экспорт+verify)`);

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
        console.error(`[ShadowVault] export "${rel}":`, err);
        failed.push({ path: rel, error: msg });
      }
      onProgress?.(i + 1, total, rel);
    }

    // Если хоть один файл не экспортировался/не верифицировался — НЕ удаляем
    // .enc. Возвращаем failed: вызывающий (disableEncryption) откатится с
    // понятной ошибкой, .enc нетронуты, plaintext не потерян.
    if (failed.length > 0) {
      console.error(
        `[ShadowVault] export: ${failed.length} файл(ов) не удалось — ` +
        `.enc НЕ удаляем, шифрование остаётся включённым (идемпотентный повтор безопасен).`
      );
      return { exported, failed };
    }

    // ── ФАЗА 2: все экспорты успешны → удаляем .enc батчем в конце ──
    console.info(`[ShadowVault] export фаза 2: удаление .enc (${exported.length} экспортировано)`);
    const encToRemove = new Set<string>(exported);
    // Добавляем orphan .enc (есть в оригинале, но не было в shadow —
    // например после неудачного decrypt); plaintext для них уже есть/нет,
    // но сами .enc больше не нужны после отключения шифрования.
    for (const rel of await this.scanEncryptedFiles()) encToRemove.add(rel);

    for (const rel of encToRemove) {
      try {
        await fsp.unlink(this.originalEncAbs(rel));
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== "ENOENT") {
          // Удаление .enc не удалось, но plaintext уже на месте и проверен —
          // данные не потеряны. Логируем; повторный disableEncryption до-удалит.
          console.error(`[ShadowVault] export: не удалось удалить .enc "${rel}":`, err);
        }
      }
    }

    console.info(`[ShadowVault] export done: ${exported.length} файлов, ${failed.length} ошибок`);
    return { exported, failed };
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
   * Настройки (verificationBlob) обновляются снаружи ПОСЛЕ успеха.
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
      if (head && detectFormat(head) !== "v2") return true;
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

  /**
   * Возвращает первый .enc файл хранилища (для probe пароля при отсутствии
   * verificationBlob). null если хранилище пустое.
   */
  async firstEncBuffer(): Promise<Uint8Array | null> {
    const encFiles = await this.scanEncryptedFiles();
    if (encFiles.length === 0) return null;
    try {
      return new Uint8Array(await fsp.readFile(this.originalEncAbs(encFiles[0])));
    } catch {
      return null;
    }
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

    console.info(`[ShadowVault] Миграция legacy → v2: проверяем ${encFiles.length} файлов.`);

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
        console.error(`[ShadowVault] Миграция "${normalizedPath}" не удалась:`, err);
        failed.push({ path: normalizedPath, error: msg });
        // Подчищаем возможный недописанный .new (atomicWrite уже чистит свой tmp,
        // но rename мог не успеть — удаляем .new если остался).
        await fsp.unlink(newEncPath).catch(() => undefined);
      }
      done++;
      onProgress?.(done, encFiles.length, normalizedPath);
    }

    console.info(
      `[ShadowVault] Миграция legacy → v2 завершена: ${migrated.length} мигрировано, ` +
      `${skipped} уже v2, ${failed.length} ошибок.`
    );
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
  private async scanEncryptedFiles(): Promise<string[]> {
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
      console.debug(`[ShadowVault:write] bypass → ${normalizedPath}`);
      return this.originalMethods.write!(normalizedPath, data, options);
    }

    const shadowPath  = this.shadowAbs(normalizedPath);
    const origEncPath = this.originalEncAbs(normalizedPath);

    console.debug(`[ShadowVault:write] ${normalizedPath} (${data.length} chars) → shadow + .enc`);

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
      console.debug(`[ShadowVault:mkdir] bypass ${normalizedPath}`);
      return this.originalMethods.mkdir!(normalizedPath);
    }
    console.debug(`[ShadowVault:mkdir] ${normalizedPath} → shadow + original`);
    await Promise.all([
      fsp.mkdir(this.shadowAbs(normalizedPath),   { recursive: true }),
      fsp.mkdir(this.originalAbs(normalizedPath), { recursive: true }),
    ]);
  }

  private async patchedRemove(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      console.debug(`[ShadowVault:remove] bypass ${normalizedPath}`);
      return this.originalMethods.remove!(normalizedPath);
    }
    console.debug(`[ShadowVault:remove] ${normalizedPath} → shadow + .enc`);
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
      console.debug(`[ShadowVault:rename] bypass ${normalizedPath} → ${newNormalizedPath}`);
      return this.originalMethods.rename!(normalizedPath, newNormalizedPath);
    }

    const newShadow   = this.shadowAbs(newNormalizedPath);
    const newOrigEnc  = this.originalEncAbs(newNormalizedPath);
    const oldShadow   = this.shadowAbs(normalizedPath);
    const oldOrigEnc  = this.originalEncAbs(normalizedPath);

    console.debug(`[ShadowVault:rename] ${normalizedPath} → ${newNormalizedPath}`);

    await fsp.mkdir(nodePath.dirname(newShadow),  { recursive: true });
    await fsp.mkdir(nodePath.dirname(newOrigEnc), { recursive: true });

    const shadowExists = await fileExists(oldShadow);
    const encExists = await fileExists(oldOrigEnc);
    console.debug(
      `[ShadowVault:rename] oldShadow exists=${shadowExists}, oldEnc exists=${encExists}`
    );

    if (shadowExists) {
      await fsp.rename(oldShadow, newShadow);
    } else {
      console.warn(`[ShadowVault:rename] oldShadow ${oldShadow} НЕ НАЙДЕН — пропускаем shadow rename`);
    }

    if (encExists) {
      await fsp.rename(oldOrigEnc, newOrigEnc);
    } else {
      console.warn(`[ShadowVault:rename] oldEnc ${oldOrigEnc} НЕ НАЙДЕН — пропускаем .enc rename`);
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

