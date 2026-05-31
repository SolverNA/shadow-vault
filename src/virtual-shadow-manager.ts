/**
 * Виртуальный shadow manager для кросс-платформенной работы
 * Хранит расшифрованные файлы в памяти вместо отдельной директории на диске
 */

import { WebCryptoEngine } from "./web-crypto-engine";
import { PlatformAdapter } from "./platform-adapter";
import { detectFormat, plaintextSizeFromContainer } from "./crypto/format";
import { migrateBuffer, probeLegacyPassword } from "./crypto/migration";
import type { LegacyVariant } from "./crypto/legacy";

export class VirtualShadowManager {
  private cache: Map<string, ArrayBuffer> = new Map();
  private engine: WebCryptoEngine;
  private adapter: PlatformAdapter;

  constructor(engine: WebCryptoEngine, adapter: PlatformAdapter) {
    this.engine = engine;
    this.adapter = adapter;
  }

  /**
   * Читает файл (расшифровывает из .enc или берёт из кэша)
   * @param normalizedPath - путь к файлу (без .enc)
   * @returns расшифрованные данные
   */
  async read(normalizedPath: string): Promise<ArrayBuffer> {
    // 1. Проверяем кэш — возвращаем КОПИЮ, чтобы мутация потребителем не
    //    портила кэшированный буфер (рассинхрон с .enc).
    if (this.cache.has(normalizedPath)) {
      return this.cache.get(normalizedPath)!.slice(0);
    }

    // 2. Читаем .enc из хранилища
    const encPath = normalizedPath + ".enc";
    const encrypted = await this.adapter.readBinary(encPath);

    // 3. Расшифровываем
    const decrypted = await this.engine.decryptBuffer(encrypted);

    // 4. Кэшируем (свой экземпляр) и отдаём отдельную КОПИЮ наружу.
    this.cache.set(normalizedPath, decrypted);

    return decrypted.slice(0);
  }

  /**
   * Записывает файл (сохраняет в кэш и шифрует в .enc)
   * @param normalizedPath - путь к файлу (без .enc)
   * @param data - данные для записи
   */
  async write(normalizedPath: string, data: ArrayBuffer): Promise<void> {
    // 1. Сохраняем в кэш КОПИЮ — иначе последующая мутация переданного буфера
    //    потребителем испортит кэш и приведёт к рассинхрону с .enc.
    this.cache.set(normalizedPath, data.slice(0));

    // 2. Шифруем (из исходного буфера — он уже зафиксирован)
    const encrypted = await this.engine.encryptBuffer(data);

    // 3. Пишем .enc в хранилище
    const encPath = normalizedPath + ".enc";
    await this.adapter.writeBinary(encPath, encrypted);
  }

  /**
   * Проверяет существование файла
   * @param normalizedPath - путь к файлу (без .enc)
   */
  async exists(normalizedPath: string): Promise<boolean> {
    // Проверяем кэш или .enc файл
    if (this.cache.has(normalizedPath)) {
      return true;
    }
    const encPath = normalizedPath + ".enc";
    return await this.adapter.exists(encPath);
  }

  /**
   * Удаляет файл
   * @param normalizedPath - путь к файлу (без .enc)
   */
  async remove(normalizedPath: string): Promise<void> {
    // Удаляем из кэша
    this.cache.delete(normalizedPath);

    // Удаляем .enc файл
    const encPath = normalizedPath + ".enc";
    await this.adapter.remove(encPath);
  }

  /**
   * Переименовывает файл
   * @param oldPath - старый путь (без .enc)
   * @param newPath - новый путь (без .enc)
   */
  async rename(oldPath: string, newPath: string): Promise<void> {
    // Если файл в кэше, переносим
    if (this.cache.has(oldPath)) {
      const data = this.cache.get(oldPath)!;
      this.cache.delete(oldPath);
      this.cache.set(newPath, data);
    }

    // Переименовываем .enc файл (читаем + пишем + удаляем)
    const oldEncPath = oldPath + ".enc";
    const newEncPath = newPath + ".enc";

    const encrypted = await this.adapter.readBinary(oldEncPath);
    await this.adapter.writeBinary(newEncPath, encrypted);
    await this.adapter.remove(oldEncPath);
  }

  /**
   * Копирует файл
   * @param srcPath - исходный путь (без .enc)
   * @param dstPath - целевой путь (без .enc)
   */
  async copy(srcPath: string, dstPath: string): Promise<void> {
    // Копируем в кэше если есть
    if (this.cache.has(srcPath)) {
      const data = this.cache.get(srcPath)!;
      // Создаём копию ArrayBuffer
      const copy = data.slice(0);
      this.cache.set(dstPath, copy);
    }

    // Копируем .enc файл
    const srcEncPath = srcPath + ".enc";
    const dstEncPath = dstPath + ".enc";

    const encrypted = await this.adapter.readBinary(srcEncPath);
    await this.adapter.writeBinary(dstEncPath, encrypted);
  }

  /**
   * Получает статистику файла
   * @param normalizedPath - путь к файлу (без .enc)
   */
  async stat(normalizedPath: string): Promise<{ size: number; mtime: number } | null> {
    const encPath = normalizedPath + ".enc";
    const s = await this.adapter.stat(encPath);
    if (!s) return null;

    // Размер plaintext, а не .enc. Если файл в кэше — точный размер из кэша.
    if (this.cache.has(normalizedPath)) {
      return { size: this.cache.get(normalizedPath)!.byteLength, mtime: s.mtime };
    }

    // Иначе оцениваем по содержимому .enc без расшифровки (для chunked — по
    // префиксам длин сегментов). Mobile-адаптер читает файл целиком, но для
    // согласованности размера это допустимо (файлы обычно небольшие).
    try {
      const buf = new Uint8Array(await this.adapter.readBinary(encPath));
      return { size: plaintextSizeFromContainer(buf), mtime: s.mtime };
    } catch {
      // Не удалось прочитать .enc — отдаём сырой размер (лучше, чем ничего).
      return { size: s.size, mtime: s.mtime };
    }
  }

  /**
   * Список файлов в директории
   * @param dirPath - путь к директории
   * @returns список файлов и папок (без .enc расширений)
   */
  async list(dirPath: string): Promise<{ files: string[]; folders: string[] }> {
    const result = await this.adapter.list(dirPath);

    // Убираем .enc расширения из файлов
    const files = result.files
      .filter(f => f.endsWith(".enc"))
      .map(f => f.slice(0, -4)); // убираем ".enc"

    return { files, folders: result.folders };
  }

  /**
   * Очищает кэш (при блокировке vault)
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Получает размер кэша в байтах
   */
  getCacheSize(): number {
    let size = 0;
    for (const buffer of this.cache.values()) {
      size += buffer.byteLength;
    }
    return size;
  }

  /**
   * Получает количество файлов в кэше
   */
  getCacheCount(): number {
    return this.cache.size;
  }

  /**
   * Проверяет, есть ли файл в кэше
   */
  isInCache(normalizedPath: string): boolean {
    return this.cache.has(normalizedPath);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ФАЗА 4: миграция legacy → v2 (mobile, последовательно через Vault API)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Рекурсивно собирает все .enc файлы хранилища (полные пути с .enc).
   * Папка configDir (.obsidian) пропускается — там нет наших шифрованных заметок.
   */
  private async scanEncFiles(configDir: string): Promise<string[]> {
    const out: string[] = [];
    const walk = async (dir: string): Promise<void> => {
      const { files, folders } = await this.adapter.list(dir);
      for (const f of files) {
        if (f.endsWith(".enc")) out.push(f);
      }
      for (const sub of folders) {
        const name = sub.split("/").pop() ?? "";
        if (name.startsWith(".") || name === configDir) continue;
        await walk(sub);
      }
    };
    await walk("");
    return out;
  }

  /**
   * Проверяет, есть ли в хранилище хотя бы один legacy .enc (не v2 по MAGIC).
   */
  async hasLegacyFiles(configDir: string): Promise<boolean> {
    const enc = await this.scanEncFiles(configDir);
    for (const p of enc) {
      try {
        const buf = new Uint8Array(await this.adapter.readBinary(p));
        // Legacy — ТОЛЬКО позитивно. v2/v2-chunked и пустые/битые (unknown) — нет.
        const fmt = detectFormat(buf);
        if (fmt === "legacy-node" || fmt === "legacy-web") return true;
      } catch {
        // нечитаемый файл — пропускаем
      }
    }
    return false;
  }

  /**
   * Проверяет пароль через trial-decrypt первого LEGACY .enc (для хранилищ
   * без verificationBlob). Возвращает:
   *   - "LEGACY_OK"             — нашёлся legacy-файл и пароль к нему подошёл;
   *   - "LEGACY_WRONG_PASSWORD" — нашёлся legacy-файл, но пароль не подошёл;
   *   - "NOT_LEGACY"            — legacy-файлов нет (всё v2/пусто) → проверять нечего.
   * Пустые (0 байт) и v2/v2-chunked файлы пропускаются — не legacy.
   */
  async probePassword(
    configDir: string,
    password: string
  ): Promise<"NOT_LEGACY" | "LEGACY_OK" | "LEGACY_WRONG_PASSWORD"> {
    const enc = await this.scanEncFiles(configDir);
    for (const p of enc) {
      try {
        const buf = new Uint8Array(await this.adapter.readBinary(p));
        const fmt = detectFormat(buf);
        if (fmt !== "legacy-node" && fmt !== "legacy-web") continue;
        const res = await probeLegacyPassword(buf, password);
        // probe для legacy-образца вернёт LEGACY_OK или LEGACY_WRONG_PASSWORD.
        return res.status === "LEGACY_OK" ? "LEGACY_OK" : "LEGACY_WRONG_PASSWORD";
      } catch {
        // продолжаем к следующему
      }
    }
    return "NOT_LEGACY"; // legacy-файлов нет
  }

  /**
   * Самовосстановление блоба для v2-хранилища без verificationBlob (mobile).
   * Пытается расшифровать первый ВАЛИДНЫЙ v2/v2-chunked .enc текущим движком
   * (ключ уже выведен из email+password). Успех → пароль верный. Провал
   * (GCM auth) → неверный пароль. Если валидных v2-файлов нет — null
   * (пустое/новое хранилище, проверять нечего).
   *
   * @returns true — пароль верный; false — неверный; null — нет v2-файлов.
   */
  async validateV2Password(configDir: string): Promise<boolean | null> {
    const enc = await this.scanEncFiles(configDir);
    for (const p of enc) {
      try {
        const buf = new Uint8Array(await this.adapter.readBinary(p));
        const fmt = detectFormat(buf);
        if (fmt !== "v2" && fmt !== "v2-chunked") continue; // пропускаем пустые/legacy/битые
        try {
          await this.engine.decryptBuffer(buf);
          return true; // расшифровалось текущим ключом → пароль верный
        } catch {
          return false; // GCM auth fail → неверный пароль
        }
      } catch {
        // нечитаемый файл — к следующему
      }
    }
    return null; // валидных v2-файлов нет
  }

  /**
   * Мигрирует все legacy .enc → v2 последовательно (mobile через Vault API).
   *
   * Пофайлово: read → migrateBuffer (legacy-decrypt + re-encrypt v2 +
   * round-trip verify) → writeBinary поверх того же .enc. На mobile нет
   * fs.rename, поэтому writeBinary — это запись через Obsidian adapter (он
   * сам пишет атомарно на уровне ОС). v2 пишется только ПОСЛЕ успешного
   * round-trip verify, поэтому окно потери данных минимально.
   * Идемпотентность: уже-v2 файлы пропускаются (skipped-v2).
   */
  /**
   * Пере-шифровывает все .enc новым ключом (смена пароля/email на mobile).
   *
   * Пофайлово: read(.enc) → decrypt СТАРЫМ движком (this.engine) → encrypt
   * НОВЫМ движком → round-trip verify (decrypt новым движком, сравнение байт)
   * → writeBinary поверх .enc. Новый шифртекст пишется ТОЛЬКО после успешного
   * round-trip verify в памяти, поэтому окно повреждения данных на каждый файл
   * минимально (одна атомарная writeBinary через Obsidian adapter).
   *
   * НЮАНС mobile: настоящей кросс-файловой атомарности (как rename .new→.enc на
   * desktop) нет. Если процесс упадёт в середине, часть файлов будет под новым
   * ключом, часть под старым. Для восстановления см. main.changeCredentials:
   * verificationBlob обновляется только после полного успеха, а смешанное
   * состояние читаемо, т.к. оба ключа известны во время прогона (повторный
   * запуск с новым паролем дочитает остаток — будущая доработка).
   *
   * После успеха движок чтения переключается на новый ключ и кэш очищается.
   *
   * @param newEngine движок с уже загруженным НОВЫМ ключом
   */
  async reEncryptAll(
    configDir: string,
    newEngine: WebCryptoEngine,
    onProgress?: (done: number, total: number) => void
  ): Promise<void> {
    const encFiles = await this.scanEncFiles(configDir);
    const total = encFiles.length;

    for (let i = 0; i < total; i++) {
      const encPath = encFiles[i];
      const buf = new Uint8Array(await this.adapter.readBinary(encPath));
      if (buf.length === 0) {
        // Legacy 0-байтный .enc → пустой plaintext. Пере-шифруем в ВАЛИДНЫЙ
        // v2-контейнер новым ключом (единый контракт пустых файлов), а не
        // оставляем 0 байт.
        const reencEmpty = await newEngine.encryptBuffer(new Uint8Array(0));
        await this.adapter.writeBinary(encPath, reencEmpty);
        this.cache.delete(encPath.slice(0, -4));
        onProgress?.(i + 1, total);
        continue;
      }
      // Расшифровываем старым ключом
      const plain = await this.engine.decryptBuffer(buf);
      // Шифруем новым
      const reenc = await newEngine.encryptBuffer(plain);
      // Round-trip verify: новый шифртекст обязан расшифроваться в исходник
      const check = new Uint8Array(await newEngine.decryptBuffer(reenc));
      const orig = new Uint8Array(plain);
      if (check.length !== orig.length) {
        throw new Error(`[VirtualShadow] round-trip verify не прошёл (длина): ${encPath}`);
      }
      for (let k = 0; k < check.length; k++) {
        if (check[k] !== orig[k]) {
          throw new Error(`[VirtualShadow] round-trip verify не прошёл (байты): ${encPath}`);
        }
      }
      await this.adapter.writeBinary(encPath, reenc);
      this.cache.delete(encPath.slice(0, -4));
      onProgress?.(i + 1, total);
    }

    // Переключаем движок чтения на новый ключ и чистим кэш.
    this.engine = newEngine;
    this.cache.clear();
  }

  async migrateLegacyToV2(
    configDir: string,
    password: string,
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<{ migrated: number; skipped: number; failed: Array<{ path: string; error: string }> }> {
    const encFiles = await this.scanEncFiles(configDir);
    let migrated = 0;
    let skipped = 0;
    let done = 0;
    const failed: Array<{ path: string; error: string }> = [];
    let hint: LegacyVariant | undefined;

    for (const encPath of encFiles) {
      try {
        const buf = new Uint8Array(await this.adapter.readBinary(encPath));
        const res = await migrateBuffer(buf, password, this.engine, hint);
        if (res.status === "skipped-v2") {
          skipped++;
        } else {
          hint = res.variant;
          const ab = res.v2.buffer.slice(
            res.v2.byteOffset,
            res.v2.byteOffset + res.v2.byteLength
          );
          await this.adapter.writeBinary(encPath, ab);
          // Сбрасываем кэш для этого файла — он мог содержать stale-данные.
          this.cache.delete(encPath.slice(0, -4));
          migrated++;
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[VirtualShadow] Миграция "${encPath}" не удалась:`, err);
        failed.push({ path: encPath, error: msg });
      }
      done++;
      onProgress?.(done, encFiles.length, encPath);
    }

    return { migrated, skipped, failed };
  }
}
