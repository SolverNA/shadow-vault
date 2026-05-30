/**
 * Ленивый доступ к Node-модулям файловой системы (fs/fs-promises/path/os/crypto).
 *
 * КРИТИЧНО ДЛЯ MOBILE: на Obsidian mobile (Capacitor, без Node) `require("fs")`
 * и подобные бросают исключение при ВЫЧИСЛЕНИИ модуля. Поэтому НИ ОДИН модуль,
 * который может быть загружен на mobile, не должен иметь top-level
 * `import ... from "fs"|"path"|"os"|"crypto"` — иначе бандл падает при загрузке.
 *
 * Вместо этого здесь — ленивые геттеры за runtime-гейтом isNodeRuntime()
 * (см. src/crypto/platform.ts). Реальный require("fs") происходит только при
 * первом обращении и только в desktop-ветке кода, поэтому на mobile он недостижим.
 *
 * Использование: `nfsp().readFile(...)`, `npath().join(...)`, и т.д.
 */

import { nodeRequire, isNodeRuntime } from "./crypto/platform";

export { isNodeRuntime };

type FsModule = typeof import("fs");
type FspModule = typeof import("fs/promises");
type PathModule = typeof import("path");
type OsModule = typeof import("os");
type CryptoModule = typeof import("crypto");

// Кэш загруженных модулей — require() сам кэширует, но локальный кэш дешевле
// и убирает повторную проверку гейта на горячем пути.
let _fs: FsModule | null = null;
let _fsp: FspModule | null = null;
let _path: PathModule | null = null;
let _os: OsModule | null = null;
let _crypto: CryptoModule | null = null;

/** Синхронный fs (readdirSync, existsSync, rmSync, ...). Desktop-only. */
export function nfs(): FsModule {
  return (_fs ??= nodeRequire<FsModule>("fs"));
}

/** fs/promises (readFile, writeFile, mkdir, ...). Desktop-only. */
export function nfsp(): FspModule {
  return (_fsp ??= nodeRequire<FspModule>("fs/promises"));
}

/** path (join, dirname, extname, ...). Desktop-only. */
export function npath(): PathModule {
  return (_path ??= nodeRequire<PathModule>("path"));
}

/** os (tmpdir, cpus, ...). Desktop-only. */
export function nos(): OsModule {
  return (_os ??= nodeRequire<OsModule>("os"));
}

/** node:crypto (createHash, ...). Desktop-only. WebCrypto см. crypto/platform. */
export function ncrypto(): CryptoModule {
  return (_crypto ??= nodeRequire<CryptoModule>("crypto"));
}
