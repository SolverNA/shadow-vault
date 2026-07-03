/**
 * Тесты shadow-location — вычисление расположения теневого хранилища.
 *
 * Проверяем:
 *   - платформенные app-data пути (env/platform/homedir инжектируются);
 *   - детерминированность хеша и совместимость legacy-пути (сиблинг);
 *   - fallback к сиблингу при недоступной app-data (+ logger.warn);
 *   - создание каталога resolveShadowRoot'ом.
 */

import { describe, it, expect, jest, beforeEach, afterEach } from "@jest/globals";
import * as fs from "fs";
import * as nodePath from "path";
import * as os from "os";
import {
  appDataDir,
  legacyShadowRoot,
  resolveShadowRoot,
  shadowDirHash,
  SHADOW_APP_DIR,
  SHADOW_DIR_PREFIX,
} from "../src/shadow-location";
import type { Logger } from "../src/logger";

function makeLoggerStub(): { logger: Logger; warn: jest.Mock } {
  const warn = jest.fn();
  return { logger: { warn } as unknown as Logger, warn };
}

let base: string;

beforeEach(() => {
  base = fs.mkdtempSync(nodePath.join(os.tmpdir(), "sv-location-"));
});

afterEach(() => {
  fs.rmSync(base, { recursive: true, force: true });
});

describe("shadowDirHash / legacyShadowRoot", () => {
  it("хеш детерминирован и нормализует путь", () => {
    const a = shadowDirHash("/home/user/vault");
    const b = shadowDirHash("/home/user/vault");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    // Нормализация: лишний сегмент "." не меняет хеш
    expect(shadowDirHash("/home/user/./vault")).toBe(a);
  });

  it("legacyShadowRoot — сиблинг хранилища .shadow-vault-<hash> (совместимость со старым форматом)", () => {
    const originalRoot = nodePath.join(base, "vault");
    const legacy = legacyShadowRoot(originalRoot);
    expect(nodePath.dirname(legacy)).toBe(base);
    expect(nodePath.basename(legacy)).toBe(
      SHADOW_DIR_PREFIX + shadowDirHash(originalRoot)
    );
  });
});

describe("appDataDir — платформы", () => {
  it("linux: XDG_DATA_HOME имеет приоритет", () => {
    const dir = appDataDir({
      env: { XDG_DATA_HOME: "/custom/data" },
      platform: "linux",
      homedir: () => "/home/u",
    });
    expect(dir).toBe("/custom/data");
  });

  it("linux: относительный XDG_DATA_HOME игнорируется (XDG spec) → ~/.local/share", () => {
    const dir = appDataDir({
      env: { XDG_DATA_HOME: "relative/data" },
      platform: "linux",
      homedir: () => "/home/u",
    });
    expect(dir).toBe(nodePath.join("/home/u", ".local", "share"));
  });

  it("linux: без XDG_DATA_HOME → ~/.local/share", () => {
    const dir = appDataDir({ env: {}, platform: "linux", homedir: () => "/home/u" });
    expect(dir).toBe(nodePath.join("/home/u", ".local", "share"));
  });

  it("darwin: ~/Library/Application Support", () => {
    const dir = appDataDir({ env: {}, platform: "darwin", homedir: () => "/Users/u" });
    expect(dir).toBe(nodePath.join("/Users/u", "Library", "Application Support"));
  });

  it("win32: LOCALAPPDATA предпочтительнее APPDATA (не роумится)", () => {
    const dir = appDataDir({
      env: { LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local", APPDATA: "C:\\Users\\u\\AppData\\Roaming" },
      platform: "win32",
      homedir: () => "C:\\Users\\u",
    });
    expect(dir).toBe("C:\\Users\\u\\AppData\\Local");
  });

  it("win32: без LOCALAPPDATA берётся APPDATA", () => {
    const dir = appDataDir({
      env: { APPDATA: "C:\\Users\\u\\AppData\\Roaming" },
      platform: "win32",
      homedir: () => "C:\\Users\\u",
    });
    expect(dir).toBe("C:\\Users\\u\\AppData\\Roaming");
  });

  it("win32: без env-переменных → <home>/AppData/Local", () => {
    const dir = appDataDir({ env: {}, platform: "win32", homedir: () => "/win-home" });
    expect(dir).toBe(nodePath.join("/win-home", "AppData", "Local"));
  });

  it("homedir недоступен и env пуст → null", () => {
    expect(appDataDir({ env: {}, platform: "linux", homedir: () => "" })).toBeNull();
    expect(
      appDataDir({ env: {}, platform: "darwin", homedir: () => { throw new Error("no home"); } })
    ).toBeNull();
  });
});

describe("resolveShadowRoot", () => {
  it("основной путь: <appData>/shadow-vault/shadow-<hash>, каталог создаётся", () => {
    const originalRoot = nodePath.join(base, "vault");
    const dataHome = nodePath.join(base, "xdg-data");
    const res = resolveShadowRoot(originalRoot, undefined, {
      env: { XDG_DATA_HOME: dataHome },
      platform: "linux",
      homedir: () => nodePath.join(base, "home"),
    });

    expect(res.fallback).toBe(false);
    expect(res.shadowRoot).toBe(
      nodePath.join(dataHome, SHADOW_APP_DIR, "shadow-" + shadowDirHash(originalRoot))
    );
    // Каталог реально создан — initialize()/recovery могут работать сразу
    expect(fs.existsSync(res.shadowRoot)).toBe(true);
  });

  it("путь детерминирован между вызовами (crash recovery)", () => {
    const originalRoot = nodePath.join(base, "vault");
    const opts = {
      env: { XDG_DATA_HOME: nodePath.join(base, "data") },
      platform: "linux" as NodeJS.Platform,
      homedir: () => nodePath.join(base, "home"),
    };
    const a = resolveShadowRoot(originalRoot, undefined, opts);
    const b = resolveShadowRoot(originalRoot, undefined, opts);
    expect(a.shadowRoot).toBe(b.shadowRoot);
  });

  it("разные vault'ы → разные shadow-каталоги", () => {
    const opts = {
      env: { XDG_DATA_HOME: nodePath.join(base, "data") },
      platform: "linux" as NodeJS.Platform,
      homedir: () => nodePath.join(base, "home"),
    };
    const a = resolveShadowRoot(nodePath.join(base, "vault-a"), undefined, opts);
    const b = resolveShadowRoot(nodePath.join(base, "vault-b"), undefined, opts);
    expect(a.shadowRoot).not.toBe(b.shadowRoot);
  });

  it("fallback: mkdir в app-data не удался → сиблинг vault'а + logger.warn", () => {
    const originalRoot = nodePath.join(base, "vault");
    fs.mkdirSync(originalRoot, { recursive: true });
    // XDG_DATA_HOME указывает ПОД обычный файл → mkdir падает с ENOTDIR
    const blocker = nodePath.join(base, "blocker");
    fs.writeFileSync(blocker, "not a dir");
    const { logger, warn } = makeLoggerStub();

    const res = resolveShadowRoot(originalRoot, logger, {
      env: { XDG_DATA_HOME: nodePath.join(blocker, "sub") },
      platform: "linux",
      homedir: () => "",
    });

    expect(res.fallback).toBe(true);
    expect(res.shadowRoot).toBe(legacyShadowRoot(originalRoot));
    expect(warn).toHaveBeenCalled();
  });

  it("fallback: app-data не определилась (нет home, нет env) → сиблинг + logger.warn", () => {
    const originalRoot = nodePath.join(base, "vault");
    const { logger, warn } = makeLoggerStub();

    const res = resolveShadowRoot(originalRoot, logger, {
      env: {},
      platform: "linux",
      homedir: () => "",
    });

    expect(res.fallback).toBe(true);
    expect(res.shadowRoot).toBe(legacyShadowRoot(originalRoot));
    expect(warn).toHaveBeenCalled();
  });
});
