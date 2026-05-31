/**
 * Абстракция файловой системы для кросс-платформенной работы
 * Десктоп: Node.js fs
 * Мобильные: Obsidian Vault API
 */

import { Vault, normalizePath } from "obsidian";

export interface PlatformAdapter {
  readBinary(path: string): Promise<ArrayBuffer>;
  writeBinary(path: string, data: ArrayBuffer): Promise<void>;
  exists(path: string): Promise<boolean>;
  remove(path: string): Promise<void>;
  list(path: string): Promise<{ files: string[]; folders: string[] }>;
  mkdir(path: string): Promise<void>;
  stat(path: string): Promise<{ size: number; mtime: number } | null>;
}

/**
 * Мобильная реализация через Obsidian Vault API
 */
export class MobileAdapter implements PlatformAdapter {
  constructor(private vault: Vault) {}

  async readBinary(path: string): Promise<ArrayBuffer> {
    const normalized = normalizePath(path);
    return await this.vault.adapter.readBinary(normalized);
  }

  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    const normalized = normalizePath(path);
    // Создаём родительские директории если нужно
    const parts = normalized.split("/");
    if (parts.length > 1) {
      const dir = parts.slice(0, -1).join("/");
      await this.mkdir(dir);
    }
    await this.vault.adapter.writeBinary(normalized, data);
  }

  async exists(path: string): Promise<boolean> {
    const normalized = normalizePath(path);
    return await this.vault.adapter.exists(normalized);
  }

  async remove(path: string): Promise<void> {
    const normalized = normalizePath(path);
    const exists = await this.vault.adapter.exists(normalized);
    if (!exists) return;

    // Проверяем это файл или папка
    try {
      await this.vault.adapter.remove(normalized);
    } catch (err) {
      // Если это папка, удаляем рекурсивно
      await this.vault.adapter.rmdir(normalized, true);
    }
  }

  async list(path: string): Promise<{ files: string[]; folders: string[] }> {
    const normalized = normalizePath(path);
    try {
      const result = await this.vault.adapter.list(normalized);
      return {
        files: result.files,
        folders: result.folders,
      };
    } catch {
      return { files: [], folders: [] };
    }
  }

  async mkdir(path: string): Promise<void> {
    const normalized = normalizePath(path);
    const exists = await this.vault.adapter.exists(normalized);
    if (!exists) {
      await this.vault.adapter.mkdir(normalized);
    }
  }

  async stat(path: string): Promise<{ size: number; mtime: number } | null> {
    const normalized = normalizePath(path);
    try {
      const stat = await this.vault.adapter.stat(normalized);
      if (!stat) return null;
      return {
        size: stat.size,
        mtime: stat.mtime,
      };
    } catch {
      return null;
    }
  }
}
