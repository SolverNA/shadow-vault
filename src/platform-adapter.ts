/**
 * Абстракция файловой системы для кросс-платформенной работы
 * Десктоп: Node.js fs
 * Мобильные: Obsidian Vault API
 */

import { Vault, normalizePath } from "obsidian";
import { nfsp, npath } from "./node-fs";

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
 * Десктопная реализация через Node.js fs
 */
export class DesktopAdapter implements PlatformAdapter {
  constructor(private basePath: string) {}

  async readBinary(path: string): Promise<ArrayBuffer> {
    const fullPath = npath().join(this.basePath, path);
    const buf = await nfsp().readFile(fullPath);
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }

  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    const nodePath = npath();
    const fsp = nfsp();
    const fullPath = nodePath.join(this.basePath, path);
    await fsp.mkdir(nodePath.dirname(fullPath), { recursive: true });
    await fsp.writeFile(fullPath, Buffer.from(data));
  }

  async exists(path: string): Promise<boolean> {
    const fullPath = npath().join(this.basePath, path);
    try {
      await nfsp().access(fullPath);
      return true;
    } catch {
      return false;
    }
  }

  async remove(path: string): Promise<void> {
    const fsp = nfsp();
    const fullPath = npath().join(this.basePath, path);
    try {
      const stat = await fsp.stat(fullPath);
      if (stat.isDirectory()) {
        await fsp.rm(fullPath, { recursive: true, force: true });
      } else {
        await fsp.unlink(fullPath);
      }
    } catch (err: any) {
      if (err.code !== "ENOENT") throw err;
    }
  }

  async list(path: string): Promise<{ files: string[]; folders: string[] }> {
    const nodePath = npath();
    const fullPath = nodePath.join(this.basePath, path);
    try {
      const entries = await nfsp().readdir(fullPath, { withFileTypes: true });
      const files: string[] = [];
      const folders: string[] = [];

      for (const entry of entries) {
        const relativePath = nodePath.join(path, entry.name);
        if (entry.isDirectory()) {
          folders.push(relativePath);
        } else {
          files.push(relativePath);
        }
      }

      return { files, folders };
    } catch (err: any) {
      if (err.code === "ENOENT") return { files: [], folders: [] };
      throw err;
    }
  }

  async mkdir(path: string): Promise<void> {
    const fullPath = npath().join(this.basePath, path);
    await nfsp().mkdir(fullPath, { recursive: true });
  }

  async stat(path: string): Promise<{ size: number; mtime: number } | null> {
    const fullPath = npath().join(this.basePath, path);
    try {
      const stat = await nfsp().stat(fullPath);
      return {
        size: stat.size,
        mtime: stat.mtimeMs,
      };
    } catch (err: any) {
      if (err.code === "ENOENT") return null;
      throw err;
    }
  }
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
