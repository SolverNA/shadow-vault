/**
 * Вычисление расположения теневого хранилища (shadow vault) — единственный
 * источник правды для этого пути (используется shadow-vault-manager и
 * session-manager).
 *
 * ПОЧЕМУ НЕ СИБЛИНГ ХРАНИЛИЩА: раньше shadow создавался рядом с vault'ом
 * (`dirname(originalRoot)/.shadow-vault-<hash>`). Если vault лежит внутри
 * Dropbox/iCloud/OneDrive/Syncthing-папки (типичная мотивация шифровать
 * заметки!), полная РАСШИФРОВАННАЯ копия хранилища синхронизировалась в
 * облако на время каждой сессии, а при краше (recovery-shadow остаётся на
 * диске) — навсегда. Поэтому shadow теперь живёт в локальной app-data
 * директории пользователя, которая в облачный sync не попадает:
 *
 *   Linux:   $XDG_DATA_HOME || ~/.local/share
 *   macOS:   ~/Library/Application Support
 *   Windows: %LOCALAPPDATA% || %APPDATA% || ~/AppData/Local
 *            (LOCALAPPDATA предпочтительнее — не роумится между машинами)
 *
 *   + поддиректория плагина: <appData>/shadow-vault/shadow-<hash>
 *
 * <hash> — тот же детерминированный sha256-хеш от originalRoot, что и раньше:
 * важно для crash recovery после перезапуска (путь стабилен между сессиями).
 *
 * FALLBACK: если app-data директорию определить/создать не удалось —
 * возвращаемся к старому поведению (сиблинг) с logger.warn.
 *
 * MOBILE: модуль desktop-only (top-level node-импорты) — импортируется
 * только из shadow-vault-manager/session-manager, которые main.ts грузит
 * лениво и только на desktop.
 */

import * as fs from "fs";
import * as nodePath from "path";
import * as os from "os";
import * as crypto from "crypto";
import type { Logger } from "./logger";

/** Префикс имени legacy shadow-каталога (сиблинг хранилища, до v2.x). */
export const SHADOW_DIR_PREFIX = ".shadow-vault-";

/** Имя поддиректории плагина внутри app-data (совпадает с manifest.id). */
export const SHADOW_APP_DIR = "shadow-vault";

/** Инъекция окружения для тестов; по умолчанию — реальные значения процесса. */
export interface ShadowLocationEnv {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  homedir?: () => string;
}

export interface ShadowRootResolution {
  /** Абсолютный путь к теневому хранилищу (каталог уже создан, если !fallback). */
  shadowRoot: string;
  /** true — app-data недоступна, использовано старое поведение (сиблинг vault'а). */
  fallback: boolean;
}

/** Детерминированный хеш пути хранилища — стабильное имя shadow-каталога. */
export function shadowDirHash(originalRoot: string): string {
  return crypto
    .createHash("sha256")
    .update(nodePath.normalize(originalRoot))
    .digest("hex")
    .slice(0, 16);
}

/**
 * СТАРОЕ расположение shadow (до переноса в app-data): сиблинг хранилища.
 * Нужно в двух ролях:
 *   1) fallback, когда app-data недоступна;
 *   2) recovery-совместимость — после обновления плагина здесь может лежать
 *      recovery-shadow от крашнувшейся сессии старой версии (см. SessionManager).
 */
export function legacyShadowRoot(originalRoot: string): string {
  const norm = nodePath.normalize(originalRoot);
  return nodePath.join(nodePath.dirname(norm), SHADOW_DIR_PREFIX + shadowDirHash(norm));
}

/** Возвращает homedir или null (пустая строка/ошибка → null). */
function safeHome(homedir: () => string): string | null {
  try {
    const h = homedir();
    return h && h.length > 0 ? h : null;
  } catch {
    return null;
  }
}

/**
 * Платформенная app-data директория пользователя или null, если определить
 * не удалось. Electron `app.getPath("userData")` из плагина Obsidian напрямую
 * недоступен (без remote), поэтому надёжнее process.env + os.homedir().
 */
export function appDataDir(opts: ShadowLocationEnv = {}): string | null {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const homedir = opts.homedir ?? os.homedir;

  if (platform === "win32") {
    // LOCALAPPDATA предпочтительнее APPDATA (Roaming): не синхронизируется
    // между машинами доменного профиля.
    if (env.LOCALAPPDATA) return env.LOCALAPPDATA;
    if (env.APPDATA) return env.APPDATA;
    const home = safeHome(homedir);
    return home ? nodePath.join(home, "AppData", "Local") : null;
  }

  if (platform === "darwin") {
    const home = safeHome(homedir);
    return home ? nodePath.join(home, "Library", "Application Support") : null;
  }

  // Linux и прочие unix: XDG Base Directory spec.
  // Относительный XDG_DATA_HOME по спецификации игнорируется.
  if (env.XDG_DATA_HOME && nodePath.isAbsolute(env.XDG_DATA_HOME)) {
    return env.XDG_DATA_HOME;
  }
  const home = safeHome(homedir);
  return home ? nodePath.join(home, ".local", "share") : null;
}

/**
 * Вычисляет (и создаёт) каталог теневого хранилища для данного vault'а.
 *
 * Основной путь: <appData>/shadow-vault/shadow-<hash>. Каталог создаётся
 * сразу (mkdirSync recursive) — так провал прав/ФС обнаруживается здесь же
 * и срабатывает fallback, а не падение позже в initialize().
 *
 * Fallback (app-data не определилась или mkdir не удался): старое
 * поведение — сиблинг хранилища `dirname(originalRoot)/.shadow-vault-<hash>`
 * с logger.warn (plaintext может попасть в облачный sync — см. шапку модуля).
 */
export function resolveShadowRoot(
  originalRoot: string,
  logger?: Logger,
  opts: ShadowLocationEnv = {}
): ShadowRootResolution {
  const norm = nodePath.normalize(originalRoot);
  const appData = appDataDir(opts);

  if (appData) {
    const shadowRoot = nodePath.join(
      appData,
      SHADOW_APP_DIR,
      "shadow-" + shadowDirHash(norm)
    );
    try {
      fs.mkdirSync(shadowRoot, { recursive: true });
      return { shadowRoot, fallback: false };
    } catch (err) {
      logger?.warn("shadow", "app-data недоступна для shadow — fallback к сиблингу хранилища (риск попадания plaintext в облачный sync)", {
        appDataPath: shadowRoot,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  } else {
    logger?.warn("shadow", "не удалось определить app-data директорию — fallback к сиблингу хранилища (риск попадания plaintext в облачный sync)");
  }

  return { shadowRoot: legacyShadowRoot(norm), fallback: true };
}
