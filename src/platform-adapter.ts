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
  /**
   * ОРИГИНАЛЬНЫЕ (до-патчевые) методы vault.adapter, захваченные через bind
   * в конструкторе.
   *
   * КРИТИЧНО: AdapterPatcher позже подменяет методы ТОГО ЖЕ объекта
   * vault.adapter. Если бы MobileAdapter обращался к this.vault.adapter.*
   * в рантайме, он попадал бы в патченные версии → бесконечная рекурсия
   * (патченный read("note.md") → VSM.read → readBinary("note.md.enc") →
   * патченный readBinary → VSM.read → "note.md.enc.enc" → ∞).
   *
   * Поэтому MobileAdapter ОБЯЗАН создаваться ДО AdapterPatcher.patch()
   * (порядок гарантирует main.onUnlockMobile).
   */
  private fs: {
    readBinary: (path: string) => Promise<ArrayBuffer>;
    writeBinary: (path: string, data: ArrayBuffer) => Promise<void>;
    exists: (path: string) => Promise<boolean>;
    remove: (path: string) => Promise<void>;
    rmdir: (path: string, recursive: boolean) => Promise<void>;
    list: (path: string) => Promise<{ files: string[]; folders: string[] }>;
    mkdir: (path: string) => Promise<void>;
    stat: (path: string) => Promise<{ size: number; mtime: number } | null>;
  };

  constructor(vault: Vault) {
    const adapter = vault.adapter;
    this.fs = {
      readBinary: adapter.readBinary.bind(adapter),
      writeBinary: adapter.writeBinary.bind(adapter),
      exists: adapter.exists.bind(adapter),
      remove: adapter.remove.bind(adapter),
      rmdir: adapter.rmdir.bind(adapter),
      list: adapter.list.bind(adapter),
      mkdir: adapter.mkdir.bind(adapter),
      stat: adapter.stat.bind(adapter),
    };
  }

  async readBinary(path: string): Promise<ArrayBuffer> {
    const normalized = normalizePath(path);
    return await this.fs.readBinary(normalized);
  }

  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    const normalized = normalizePath(path);
    // Создаём родительские директории если нужно
    const parts = normalized.split("/");
    if (parts.length > 1) {
      const dir = parts.slice(0, -1).join("/");
      await this.mkdir(dir);
    }
    await this.fs.writeBinary(normalized, data);
  }

  async exists(path: string): Promise<boolean> {
    const normalized = normalizePath(path);
    return await this.fs.exists(normalized);
  }

  async remove(path: string): Promise<void> {
    const normalized = normalizePath(path);
    const exists = await this.fs.exists(normalized);
    if (!exists) return;

    // Проверяем это файл или папка
    try {
      await this.fs.remove(normalized);
    } catch (err) {
      // Если это папка, удаляем рекурсивно
      await this.fs.rmdir(normalized, true);
    }
  }

  async list(path: string): Promise<{ files: string[]; folders: string[] }> {
    const normalized = normalizePath(path);
    try {
      const result = await this.fs.list(normalized);
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
    const exists = await this.fs.exists(normalized);
    if (!exists) {
      await this.fs.mkdir(normalized);
    }
  }

  async stat(path: string): Promise<{ size: number; mtime: number } | null> {
    const normalized = normalizePath(path);
    try {
      const stat = await this.fs.stat(normalized);
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
