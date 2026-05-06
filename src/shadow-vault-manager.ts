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
import { CryptoEngine } from "./crypto-engine";
import { IDataAdapter, AdapterStat, DataWriteOptions, ListedFiles } from "./adapter-types";

/** Суффикс зашифрованных файлов в оригинальном хранилище */
const ENCRYPTED_EXT = ".enc";

/** Размер криптографического заголовка: IV (12 б) + AuthTag (16 б) */
const CRYPTO_HEADER_SIZE = 28;

export class ShadowVaultManager {
  private readonly engine: CryptoEngine;
  /** Абсолютный путь к оригинальному (зашифрованному) хранилищу */
  readonly originalRoot: string;
  /** Абсолютный путь к теневому (расшифрованному) хранилищу */
  readonly shadowRoot: string;

  private patched = false;
  private originalMethods: Partial<IDataAdapter> = {};

  constructor(engine: CryptoEngine, originalRoot: string, shadowRoot?: string) {
    this.engine = engine;
    this.originalRoot = nodePath.normalize(originalRoot);

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
      normalizedPath === ".obsidian" ||
      normalizedPath.startsWith(".obsidian/")
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

    console.info(`[ShadowVault] Миграция: обнаружено ${plainFiles.length} незашифрованных файлов.`);

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
        console.info(`[ShadowVault] Зашифрован: "${normalizedPath}"`);
      } catch (err) {
        console.error(`[ShadowVault] Ошибка шифрования "${normalizedPath}":`, err);
        // Продолжаем с остальными файлами
      }
    }

    console.info(`[ShadowVault] Миграция завершена: ${done}/${plainFiles.length}`);
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
      if (entry.name.startsWith(".") && entry.name !== ".obsidian") continue;
      // Временные файлы атомарных операций
      if (
        entry.name.endsWith(".tmp")       ||
        entry.name.endsWith(".shadowtmp") ||
        entry.name.endsWith(".sessiontmp")
      ) continue;

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
      if (
        entry.name.endsWith(ENCRYPTED_EXT)  ||
        entry.name.endsWith(".tmp")          ||
        entry.name.endsWith(".shadowtmp")    ||
        entry.name.endsWith(".sessiontmp")
      ) continue;

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

// ═══════════════════════════════════════════════════════════════════════
// Модульные утилиты
// ═══════════════════════════════════════════════════════════════════════

async function fileExists(absPath: string): Promise<boolean> {
  try {
    await fsp.access(absPath);
    return true;
  } catch {
    return false;
  }
}

async function atomicWrite(absPath: string, data: Buffer): Promise<void> {
  const tmpPath = absPath + ".shadowtmp";
  try {
    await fsp.writeFile(tmpPath, data);
    await fsp.rename(tmpPath, absPath);
  } catch (err) {
    await fsp.unlink(tmpPath).catch(() => undefined);
    throw err;
  }
}
