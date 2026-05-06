/**
 * ShadowVaultManager — ядро VFS-слоя плагина ShadowVault.
 *
 * Реализует паттерн "proxy через monkey-patching":
 *   - Сохраняет ссылки на оригинальные методы адаптера Obsidian.
 *   - Заменяет их обёртками, которые перенаправляют операции через
 *     два физических хранилища: Оригинальное (зашифрованное) и Теневое (расшифрованное).
 *
 * Маршрутизация операций:
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │  normalizedPath начинается с '.obsidian'?                           │
 *   │       ДА  →  пробрасываем в оригинальный адаптер БЕЗ шифрования    │
 *   │       НЕТ →  read/write через Теневое хранилище + шифрование       │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Гарантии сохранности данных:
 *   - Запись в Оригинальное хранилище всегда атомарна (tmpFile + fs.rename).
 *   - При чтении файла, которого нет в Теневом хранилище — он расшифровывается
 *     из Оригинального "на лету" (lazy decrypt / on-demand).
 *   - Метод unpatch() полностью восстанавливает оригинальный адаптер.
 */

import * as fs from "fs";
import * as fsp from "fs/promises";
import * as nodePath from "path";
import * as os from "os";
import * as crypto from "crypto";
import { CryptoEngine } from "./crypto-engine";
import { IDataAdapter, AdapterStat, DataWriteOptions, ListedFiles } from "./adapter-types";

/** Размер заголовка зашифрованного файла: IV (12 б) + AuthTag (16 б) */
const CRYPTO_HEADER_SIZE = 28;

export class ShadowVaultManager {
  private readonly engine: CryptoEngine;
  /** Абсолютный путь к зашифрованному (оригинальному) хранилищу */
  readonly originalRoot: string;
  /** Абсолютный путь к расшифрованному (теневому) хранилищу */
  readonly shadowRoot: string;

  /** Флаг — адаптер уже пропатчен */
  private patched = false;

  /**
   * Сохранённые ссылки на оригинальные методы адаптера.
   * Восстанавливаются при вызове unpatch() или при краше.
   */
  private originalMethods: Partial<IDataAdapter> = {};

  constructor(engine: CryptoEngine, originalRoot: string, shadowRoot?: string) {
    this.engine = engine;
    this.originalRoot = nodePath.normalize(originalRoot);

    // По умолчанию: /tmp/shadowvault-<детерминированный хеш оригинального пути>
    // Детерминированность важна для crash recovery — директория переживёт перезапуск
    this.shadowRoot = shadowRoot
      ? nodePath.normalize(shadowRoot)
      : nodePath.join(
          os.tmpdir(),
          "shadowvault-" + crypto
            .createHash("sha256")
            .update(this.originalRoot)
            .digest("hex")
            .slice(0, 16)
        );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Инициализация
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Создаёт директорию Теневого хранилища (если не существует).
   * НЕ удаляет существующее содержимое — это задача SessionManager (Шаг 5).
   */
  async initialize(): Promise<void> {
    await fsp.mkdir(this.shadowRoot, { recursive: true });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Monkey-patching
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Патчит методы адаптера.
   * Вызывается один раз после успешной деривации ключа.
   *
   * ВАЖНО: все обёртки обязаны совпадать по сигнатуре с интерфейсом IDataAdapter —
   * любое несовпадение типов сломает другие плагины (Dataview, Omnisearch и пр.).
   */
  patch(adapter: IDataAdapter): void {
    if (this.patched) return;

    // Сохраняем оригиналы через .bind(), чтобы контекст не потерялся
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

    // Подменяем методы — стрелочные функции сохраняют контекст this (ShadowVaultManager)
    adapter.read        = (p) => this.patchedRead(p);
    adapter.readBinary  = (p) => this.patchedReadBinary(p);
    adapter.write       = (p, d, o) => this.patchedWrite(p, d, o);
    adapter.writeBinary = (p, d, o) => this.patchedWriteBinary(p, d, o);
    adapter.append      = (p, d, o) => this.patchedAppend(p, d, o);
    adapter.process     = (p, fn, o) => this.patchedProcess(p, fn, o);
    adapter.exists      = (p, s) => this.patchedExists(p, s);
    adapter.stat        = (p) => this.patchedStat(p);
    adapter.list        = (p) => this.patchedList(p);
    adapter.mkdir       = (p) => this.patchedMkdir(p);
    adapter.remove      = (p) => this.patchedRemove(p);
    adapter.rename      = (p, np) => this.patchedRename(p, np);
    adapter.copy        = (p, np) => this.patchedCopy(p, np);
    adapter.trashSystem = (p) => this.patchedTrashSystem(p);
    adapter.trashLocal  = (p) => this.patchedTrashLocal(p);

    this.patched = true;
  }

  /**
   * Восстанавливает все оригинальные методы адаптера.
   * Вызывается при корректном завершении и в аварийных ситуациях.
   */
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

  /** normalizedPath → абсолютный путь в Теневом хранилище */
  shadowAbs(normalizedPath: string): string {
    return nodePath.join(this.shadowRoot, ...normalizedPath.split("/"));
  }

  /** normalizedPath → абсолютный путь в Оригинальном (зашифрованном) хранилище */
  originalAbs(normalizedPath: string): string {
    return nodePath.join(this.originalRoot, ...normalizedPath.split("/"));
  }

  /**
   * Возвращает true для путей, которые НЕ шифруются:
   *   - Конфигурация Obsidian (.obsidian/*)
   *   - Корень хранилища (пустая строка)
   */
  isBypassPath(normalizedPath: string): boolean {
    return (
      normalizedPath === "" ||
      normalizedPath === ".obsidian" ||
      normalizedPath.startsWith(".obsidian/")
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Ядро: расшифровка по требованию (lazy decrypt)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Гарантирует, что файл присутствует в Теневом хранилище в расшифрованном виде.
   *
   * Алгоритм:
   *   1. Если файл уже есть в теневом → ничего не делаем (кэш-хит).
   *   2. Если файл есть в оригинальном → расшифровываем потоком (для любого размера).
   *   3. Если файла нет нигде → бросаем ошибку (Obsidian должен об этом знать).
   *
   * Этот метод вызывается всеми операциями чтения. Приоритетная очередь
   * (QueueManager, Шаг 4) вызывает его для горячих файлов заранее.
   */
  async ensureDecrypted(normalizedPath: string): Promise<void> {
    const shadowPath = this.shadowAbs(normalizedPath);
    const origPath   = this.originalAbs(normalizedPath);

    // Кэш-хит: файл уже в теневом хранилище
    if (await fileExists(shadowPath)) return;

    // Файл должен быть в оригинальном хранилище
    if (!(await fileExists(origPath))) {
      throw new Error(
        `[ShadowVault] Файл не найден ни в одном хранилище: "${normalizedPath}"`
      );
    }

    // Создаём директорию в теневом хранилище (на случай вложенных путей)
    await fsp.mkdir(nodePath.dirname(shadowPath), { recursive: true });

    // Проверяем размер: если файл меньше заголовка — скорее всего пустой или не зашифрован
    const stat = await fsp.stat(origPath);
    if (stat.size === 0) {
      // Пустой файл: создаём пустой файл в теневом без расшифровки
      await fsp.writeFile(shadowPath, Buffer.alloc(0));
      return;
    }

    if (stat.size < CRYPTO_HEADER_SIZE) {
      throw new Error(
        `[ShadowVault] Файл "${normalizedPath}" повреждён: ` +
        `размер ${stat.size} б < минимального заголовка ${CRYPTO_HEADER_SIZE} б`
      );
    }

    // Потоковая расшифровка — не грузит тяжёлые файлы в RAM целиком
    await this.engine.decryptStream(origPath, shadowPath);
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
    // Node.js Buffer → ArrayBuffer (zero-copy через subarray)
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

    const shadowPath = this.shadowAbs(normalizedPath);
    const origPath   = this.originalAbs(normalizedPath);

    await fsp.mkdir(nodePath.dirname(shadowPath),   { recursive: true });
    await fsp.mkdir(nodePath.dirname(origPath),     { recursive: true });

    // 1. Записываем открытый текст в теневое хранилище
    await fsp.writeFile(shadowPath, data, "utf8");

    // 2. Шифруем и атомарно записываем в оригинальное
    //    encryptBuffer → небольшие текстовые заметки помещаются в RAM
    const encrypted = this.engine.encryptBuffer(Buffer.from(data, "utf8"));
    await atomicWrite(origPath, encrypted);
  }

  private async patchedWriteBinary(
    normalizedPath: string,
    data: ArrayBuffer,
    options?: DataWriteOptions
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.writeBinary!(normalizedPath, data, options);
    }

    const shadowPath = this.shadowAbs(normalizedPath);
    const origPath   = this.originalAbs(normalizedPath);
    const buf = Buffer.from(data);

    await fsp.mkdir(nodePath.dirname(shadowPath), { recursive: true });
    await fsp.mkdir(nodePath.dirname(origPath),   { recursive: true });

    // Теневое хранилище: сохраняем открытые байты
    await fsp.writeFile(shadowPath, buf);

    // Оригинальное: для больших файлов — потоковое шифрование
    if (buf.length > 1024 * 1024) {
      // > 1 МБ: сначала пишем в shadow, потом шифруем потоком shadow → original
      await this.engine.encryptStream(shadowPath, origPath);
    } else {
      const encrypted = this.engine.encryptBuffer(buf);
      await atomicWrite(origPath, encrypted);
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

    const shadowPath = this.shadowAbs(normalizedPath);

    // Расшифровываем текущий файл если его нет в теневом
    if (await fileExists(this.originalAbs(normalizedPath))) {
      await this.ensureDecrypted(normalizedPath);
    } else {
      // Новый файл: создаём директорию
      await fsp.mkdir(nodePath.dirname(shadowPath), { recursive: true });
    }

    // Дописываем в теневое хранилище
    await fsp.appendFile(shadowPath, data, "utf8");

    // Перечитываем полный файл и перешифровываем оригинал
    const fullContent = await fsp.readFile(shadowPath, "utf8");
    const encrypted = this.engine.encryptBuffer(Buffer.from(fullContent, "utf8"));
    await atomicWrite(this.originalAbs(normalizedPath), encrypted);
  }

  private async patchedProcess(
    normalizedPath: string,
    fn: (data: string) => string,
    options?: DataWriteOptions
  ): Promise<string> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.process!(normalizedPath, fn, options);
    }

    // process() — транзакционная операция: read → transform → write
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
    // Файлы живут в оригинальном хранилище — это источник истины
    return fileExists(this.originalAbs(normalizedPath));
  }

  private async patchedStat(normalizedPath: string): Promise<AdapterStat | null> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.stat!(normalizedPath);
    }

    // Если файл уже расшифрован в теневом — используем его стат (правильный размер)
    const shadowPath = this.shadowAbs(normalizedPath);
    const origPath   = this.originalAbs(normalizedPath);

    const statPath = (await fileExists(shadowPath)) ? shadowPath : origPath;
    try {
      const s = await fsp.stat(statPath);
      const isDir = s.isDirectory();
      const size  = (!isDir && statPath === origPath && s.size >= CRYPTO_HEADER_SIZE)
        // Вычитаем заголовок шифрования, чтобы показать реальный размер данных
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
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.list!(normalizedPath);
    }

    // Список файлов берём из оригинального хранилища — оно является источником истины.
    // Имена файлов одинаковы в обоих хранилищах (шифруется только содержимое).
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
      // Скрытые системные файлы (.session_active, .lock) не показываем Obsidian
      if (entry.name.startsWith(".") && entry.name !== ".obsidian") continue;
      const rel = prefix + entry.name;
      if (entry.isDirectory()) folders.push(rel);
      else files.push(rel);
    }

    return { files, folders };
  }

  private async patchedMkdir(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.mkdir!(normalizedPath);
    }
    // Создаём папку в обоих хранилищах синхронно
    await Promise.all([
      fsp.mkdir(this.shadowAbs(normalizedPath),   { recursive: true }),
      fsp.mkdir(this.originalAbs(normalizedPath), { recursive: true }),
    ]);
  }

  private async patchedRemove(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.remove!(normalizedPath);
    }
    // Удаляем из обоих хранилищ; игнорируем "не найдено" (ENOENT)
    await Promise.allSettled([
      fsp.unlink(this.shadowAbs(normalizedPath)),
      fsp.unlink(this.originalAbs(normalizedPath)),
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
    const newOriginal = this.originalAbs(newNormalizedPath);

    await fsp.mkdir(nodePath.dirname(newShadow),   { recursive: true });
    await fsp.mkdir(nodePath.dirname(newOriginal), { recursive: true });

    // Переименовываем в теневом (если файл там уже есть)
    const oldShadow = this.shadowAbs(normalizedPath);
    if (await fileExists(oldShadow)) {
      await fsp.rename(oldShadow, newShadow);
    }

    // Переименовываем в оригинальном (зашифрованный блоб сохраняется целиком)
    await fsp.rename(this.originalAbs(normalizedPath), newOriginal);
  }

  private async patchedCopy(
    normalizedPath: string,
    newNormalizedPath: string
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.copy!(normalizedPath, newNormalizedPath);
    }

    const newShadow   = this.shadowAbs(newNormalizedPath);
    const newOriginal = this.originalAbs(newNormalizedPath);

    await fsp.mkdir(nodePath.dirname(newShadow),   { recursive: true });
    await fsp.mkdir(nodePath.dirname(newOriginal), { recursive: true });

    const oldShadow = this.shadowAbs(normalizedPath);
    if (await fileExists(oldShadow)) {
      await fsp.copyFile(oldShadow, newShadow);
    }

    // Копируем зашифрованный блоб — повторного шифрования не нужно,
    // но новый файл должен иметь свой IV. Поэтому читаем из теневого и шифруем заново.
    await this.ensureDecrypted(normalizedPath);
    const content = await fsp.readFile(this.shadowAbs(normalizedPath));
    const encrypted = this.engine.encryptBuffer(content);
    await atomicWrite(newOriginal, encrypted);
  }

  private async patchedTrashSystem(normalizedPath: string): Promise<boolean> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.trashSystem!(normalizedPath);
    }
    // Убираем из теневого хранилища (тихо, если нет)
    await fsp.unlink(this.shadowAbs(normalizedPath)).catch(() => undefined);
    // Перемещаем оригинальный зашифрованный файл в корзину ОС
    return this.originalMethods.trashSystem!(normalizedPath);
  }

  private async patchedTrashLocal(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.trashLocal!(normalizedPath);
    }
    await fsp.unlink(this.shadowAbs(normalizedPath)).catch(() => undefined);
    return this.originalMethods.trashLocal!(normalizedPath);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Приватные утилиты (module-level, не экспортируются)
// ═══════════════════════════════════════════════════════════════════════

/** Проверяет существование файла/директории без исключений */
async function fileExists(absPath: string): Promise<boolean> {
  try {
    await fsp.access(absPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Атомарная запись Buffer в файл через временный файл + fs.rename.
 * Гарантирует: либо файл записан полностью, либо оригинал не тронут.
 * Защищает от повреждения данных при внезапном отключении питания.
 */
async function atomicWrite(absPath: string, data: Buffer): Promise<void> {
  const tmpPath = absPath + ".shadowtmp";
  try {
    await fsp.writeFile(tmpPath, data);
    await fsp.rename(tmpPath, absPath);
  } catch (err) {
    // Чистим временный файл при ошибке — не оставляем мусор
    await fsp.unlink(tmpPath).catch(() => undefined);
    throw err;
  }
}
