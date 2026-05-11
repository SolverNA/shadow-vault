/**
 * Виртуальный shadow manager для кросс-платформенной работы
 * Хранит расшифрованные файлы в памяти вместо отдельной директории на диске
 */

import { WebCryptoEngine } from "./web-crypto-engine";
import { PlatformAdapter } from "./platform-adapter";

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
    // 1. Проверяем кэш
    if (this.cache.has(normalizedPath)) {
      return this.cache.get(normalizedPath)!;
    }

    // 2. Читаем .enc из хранилища
    const encPath = normalizedPath + ".enc";
    const encrypted = await this.adapter.readBinary(encPath);

    // 3. Расшифровываем
    const decrypted = await this.engine.decryptBuffer(encrypted);

    // 4. Кэшируем
    this.cache.set(normalizedPath, decrypted);

    return decrypted;
  }

  /**
   * Записывает файл (сохраняет в кэш и шифрует в .enc)
   * @param normalizedPath - путь к файлу (без .enc)
   * @param data - данные для записи
   */
  async write(normalizedPath: string, data: ArrayBuffer): Promise<void> {
    // 1. Сохраняем в кэш
    this.cache.set(normalizedPath, data);

    // 2. Шифруем
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
    return await this.adapter.stat(encPath);
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
}
