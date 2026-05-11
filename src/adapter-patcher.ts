/**
 * Кросс-платформенный патчер адаптера Obsidian
 * Перехватывает операции с файлами и направляет их через VirtualShadowManager
 */

import { DataAdapter, DataWriteOptions } from "obsidian";
import { VirtualShadowManager } from "./virtual-shadow-manager";

export class AdapterPatcher {
  private originalMethods: Partial<DataAdapter> = {};
  private patched = false;

  constructor(
    private shadowManager: VirtualShadowManager,
    private configDir: string
  ) {}

  /**
   * Патчит методы адаптера
   */
  patch(adapter: DataAdapter): void {
    if (this.patched) return;

    // Сохраняем оригинальные методы
    this.originalMethods.read = adapter.read.bind(adapter);
    this.originalMethods.readBinary = adapter.readBinary.bind(adapter);
    this.originalMethods.write = adapter.write.bind(adapter);
    this.originalMethods.writeBinary = adapter.writeBinary.bind(adapter);
    this.originalMethods.exists = adapter.exists.bind(adapter);
    this.originalMethods.remove = adapter.remove.bind(adapter);
    this.originalMethods.rename = adapter.rename.bind(adapter);
    this.originalMethods.copy = adapter.copy.bind(adapter);
    this.originalMethods.stat = adapter.stat.bind(adapter);
    this.originalMethods.list = adapter.list.bind(adapter);

    // Подменяем методы
    adapter.read = (p) => this.patchedRead(p);
    adapter.readBinary = (p) => this.patchedReadBinary(p);
    adapter.write = (p, d, o) => this.patchedWrite(p, d, o);
    adapter.writeBinary = (p, d, o) => this.patchedWriteBinary(p, d, o);
    adapter.exists = (p, s) => this.patchedExists(p, s);
    adapter.remove = (p) => this.patchedRemove(p);
    adapter.rename = (o, n) => this.patchedRename(o, n);
    adapter.copy = (s, d) => this.patchedCopy(s, d);
    adapter.stat = (p) => this.patchedStat(p);
    adapter.list = (p) => this.patchedList(p);

    this.patched = true;
  }

  /**
   * Восстанавливает оригинальные методы адаптера
   */
  unpatch(adapter: DataAdapter): void {
    if (!this.patched) return;

    if (this.originalMethods.read) adapter.read = this.originalMethods.read;
    if (this.originalMethods.readBinary) adapter.readBinary = this.originalMethods.readBinary;
    if (this.originalMethods.write) adapter.write = this.originalMethods.write;
    if (this.originalMethods.writeBinary) adapter.writeBinary = this.originalMethods.writeBinary;
    if (this.originalMethods.exists) adapter.exists = this.originalMethods.exists;
    if (this.originalMethods.remove) adapter.remove = this.originalMethods.remove;
    if (this.originalMethods.rename) adapter.rename = this.originalMethods.rename;
    if (this.originalMethods.copy) adapter.copy = this.originalMethods.copy;
    if (this.originalMethods.stat) adapter.stat = this.originalMethods.stat;
    if (this.originalMethods.list) adapter.list = this.originalMethods.list;

    this.originalMethods = {};
    this.patched = false;
  }

  // ========== Патченные методы ==========

  private async patchedRead(normalizedPath: string): Promise<string> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.read!(normalizedPath);
    }

    const buf = await this.shadowManager.read(normalizedPath);
    const decoder = new TextDecoder();
    return decoder.decode(buf);
  }

  private async patchedReadBinary(normalizedPath: string): Promise<ArrayBuffer> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.readBinary!(normalizedPath);
    }

    return await this.shadowManager.read(normalizedPath);
  }

  private async patchedWrite(
    normalizedPath: string,
    data: string,
    options?: DataWriteOptions
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.write!(normalizedPath, data, options);
    }

    const encoder = new TextEncoder();
    const buf = encoder.encode(data);
    await this.shadowManager.write(normalizedPath, buf.buffer);
  }

  private async patchedWriteBinary(
    normalizedPath: string,
    data: ArrayBuffer,
    options?: DataWriteOptions
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.writeBinary!(normalizedPath, data, options);
    }

    await this.shadowManager.write(normalizedPath, data);
  }

  private async patchedExists(
    normalizedPath: string,
    sensitive?: boolean
  ): Promise<boolean> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.exists!(normalizedPath, sensitive);
    }

    return await this.shadowManager.exists(normalizedPath);
  }

  private async patchedRemove(normalizedPath: string): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.remove!(normalizedPath);
    }

    await this.shadowManager.remove(normalizedPath);
  }

  private async patchedRename(
    oldPath: string,
    newPath: string
  ): Promise<void> {
    const oldBypass = this.isBypassPath(oldPath);
    const newBypass = this.isBypassPath(newPath);

    // Оба пути bypass — используем оригинальный метод
    if (oldBypass && newBypass) {
      return this.originalMethods.rename!(oldPath, newPath);
    }

    // Один из путей bypass — ошибка (нельзя перемещать между зонами)
    if (oldBypass !== newBypass) {
      throw new Error("Cannot rename between encrypted and unencrypted paths");
    }

    // Оба пути зашифрованы
    await this.shadowManager.rename(oldPath, newPath);
  }

  private async patchedCopy(
    srcPath: string,
    dstPath: string
  ): Promise<void> {
    const srcBypass = this.isBypassPath(srcPath);
    const dstBypass = this.isBypassPath(dstPath);

    // Оба пути bypass — используем оригинальный метод
    if (srcBypass && dstBypass) {
      return this.originalMethods.copy!(srcPath, dstPath);
    }

    // Один из путей bypass — ошибка (нельзя копировать между зонами)
    if (srcBypass !== dstBypass) {
      throw new Error("Cannot copy between encrypted and unencrypted paths");
    }

    // Оба пути зашифрованы
    await this.shadowManager.copy(srcPath, dstPath);
  }

  private async patchedStat(
    normalizedPath: string
  ): Promise<{ ctime: number; mtime: number; size: number } | null> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.stat!(normalizedPath);
    }

    const stat = await this.shadowManager.stat(normalizedPath);
    if (!stat) return null;

    return {
      ctime: stat.mtime, // используем mtime для ctime
      mtime: stat.mtime,
      size: stat.size,
    };
  }

  private async patchedList(
    normalizedPath: string
  ): Promise<{ files: string[]; folders: string[] }> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.list!(normalizedPath);
    }

    return await this.shadowManager.list(normalizedPath);
  }

  // ========== Вспомогательные методы ==========

  /**
   * Проверяет, нужно ли пропустить шифрование для этого пути
   * @param normalizedPath - нормализованный путь
   */
  private isBypassPath(normalizedPath: string): boolean {
    // Корневая директория
    if (normalizedPath === "") return true;

    // Конфигурация плагина (.obsidian)
    if (normalizedPath === this.configDir) return true;
    if (normalizedPath.startsWith(this.configDir + "/")) return true;

    return false;
  }

  /**
   * Проверяет, запатчен ли адаптер
   */
  isPatched(): boolean {
    return this.patched;
  }
}
