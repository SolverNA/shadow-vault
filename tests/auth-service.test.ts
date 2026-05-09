/**
 * Юнит-тесты для AuthService.
 * Obsidian API не нужен — тестируем чистую логику аутентификации.
 */

import { describe, it, expect, jest } from "@jest/globals";
import { AuthService, PasswordError, SettingsCorruptedError } from "../src/auth-service";
import { DEFAULT_SETTINGS, PluginSettings } from "../src/types";

// ─────────────────────────────────────────────
// Хелперы
// ─────────────────────────────────────────────

/** Создаёт mock saveFn, который сохраняет настройки в локальную переменную */
function makeSaveFn(): {
  fn: (s: PluginSettings) => Promise<void>;
  lastSaved: () => PluginSettings | null;
} {
  let lastSaved: PluginSettings | null = null;
  const fn = jest.fn(async (s: PluginSettings) => {
    lastSaved = s;
  });
  return { fn, lastSaved: () => lastSaved };
}

// ─────────────────────────────────────────────
// Первый запуск
// ─────────────────────────────────────────────

describe("AuthService — первый запуск (saltHex === null)", () => {
  it("успешно инициализирует хранилище и возвращает разблокированный engine", async () => {
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();

    const result = await svc.authenticate("my-secure-password", DEFAULT_SETTINGS, fn);

    expect(result.isFirstRun).toBe(true);
    expect(result.engine.isUnlocked()).toBe(true);
    result.engine.destroy();
  });

  it("сохраняет saltHex и verificationBlob в settings", async () => {
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();

    await svc.authenticate("my-secure-password", DEFAULT_SETTINGS, fn);

    expect(fn).toHaveBeenCalledTimes(1);
    const saved = lastSaved()!;
    expect(saved.saltHex).toBeTruthy();
    expect(saved.saltHex).toHaveLength(64); // 32 байта → 64 hex
    expect(saved.verificationBlob).toBeTruthy();
  });

  it("разные запуски с одним паролем → разные соли (случайная соль)", async () => {
    const svc = new AuthService();
    const { fn: fn1, lastSaved: ls1 } = makeSaveFn();
    const { fn: fn2, lastSaved: ls2 } = makeSaveFn();

    await svc.authenticate("password", DEFAULT_SETTINGS, fn1);
    await svc.authenticate("password", DEFAULT_SETTINGS, fn2);

    expect(ls1()!.saltHex).not.toBe(ls2()!.saltHex);
  });

  it("бросает PasswordError при пустом пароле", async () => {
    const svc = new AuthService();
    const { fn } = makeSaveFn();

    await expect(svc.authenticate("", DEFAULT_SETTINGS, fn)).rejects.toThrow(PasswordError);
    await expect(svc.authenticate("   ", DEFAULT_SETTINGS, fn)).rejects.toThrow(PasswordError);
  });
});

// ─────────────────────────────────────────────
// Повторный вход (хранилище уже инициализировано)
// ─────────────────────────────────────────────

describe("AuthService — повторный вход", () => {
  /** Инициализирует хранилище и возвращает сохранённые настройки для следующего входа */
  async function initVault(password: string): Promise<PluginSettings> {
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();
    const result = await svc.authenticate(password, DEFAULT_SETTINGS, fn);
    result.engine.destroy();
    return lastSaved()!;
  }

  it("успешный вход с правильным паролем", async () => {
    const savedSettings = await initVault("correct-password");

    const svc = new AuthService();
    const { fn } = makeSaveFn();
    const result = await svc.authenticate("correct-password", savedSettings, fn);

    expect(result.isFirstRun).toBe(false);
    expect(result.engine.isUnlocked()).toBe(true);
    result.engine.destroy();
  });

  it("не вызывает saveFn при повторном входе", async () => {
    const savedSettings = await initVault("password");

    const svc = new AuthService();
    const { fn } = makeSaveFn();
    const result = await svc.authenticate("password", savedSettings, fn);
    result.engine.destroy();

    expect(fn).not.toHaveBeenCalled();
  });

  it("бросает PasswordError при неверном пароле", async () => {
    const savedSettings = await initVault("correct-password");

    const svc = new AuthService();
    const { fn } = makeSaveFn();

    await expect(
      svc.authenticate("wrong-password", savedSettings, fn)
    ).rejects.toThrow(PasswordError);
  });

  it("после неверного пароля engine не утекает в памяти", async () => {
    const savedSettings = await initVault("correct-password");

    const svc = new AuthService();
    const { fn } = makeSaveFn();

    await expect(
      svc.authenticate("wrong", savedSettings, fn)
    ).rejects.toThrow(PasswordError);
    // Если бы engine утёк — он бы остался в памяти в unlocked состоянии.
    // Проверяем косвенно: следующая попытка с правильным паролем должна работать нормально.
    const result = await svc.authenticate("correct-password", savedSettings, fn);
    expect(result.engine.isUnlocked()).toBe(true);
    result.engine.destroy();
  });

  it("бросает SettingsCorruptedError если verificationBlob отсутствует", async () => {
    const savedSettings = await initVault("password");
    const corruptedSettings: PluginSettings = { ...savedSettings, verificationBlob: null };

    const svc = new AuthService();
    const { fn } = makeSaveFn();

    await expect(
      svc.authenticate("password", corruptedSettings, fn)
    ).rejects.toThrow(SettingsCorruptedError);
  });

  it("бросает PasswordError если verificationBlob повреждён", async () => {
    const savedSettings = await initVault("password");
    // Подменяем blob случайным мусором — симуляция повреждения data.json
    const corruptedSettings: PluginSettings = {
      ...savedSettings,
      verificationBlob: "deadbeefdeadbeefdeadbeef",
    };

    const svc = new AuthService();
    const { fn } = makeSaveFn();

    await expect(
      svc.authenticate("password", corruptedSettings, fn)
    ).rejects.toThrow(PasswordError);
  });
});

// ─────────────────────────────────────────────
// Сквозной сценарий: создание → повторный вход → смена пароля
// ─────────────────────────────────────────────

describe("AuthService — сквозные сценарии", () => {
  it("engine из первого запуска может шифровать данные, которые расшифрует engine повторного входа", async () => {
    const svc1 = new AuthService();
    const { fn, lastSaved } = makeSaveFn();

    // Первый запуск — создаём хранилище
    const { engine: engine1 } = await svc1.authenticate("vault-password", DEFAULT_SETTINGS, fn);
    const enc = engine1.encryptBuffer(Buffer.from("Секретная заметка"));
    engine1.destroy();

    // Повторный вход с тем же паролем
    const svc2 = new AuthService();
    const { fn: fn2 } = makeSaveFn();
    const { engine: engine2 } = await svc2.authenticate("vault-password", lastSaved()!, fn2);
    const dec = engine2.decryptBuffer(enc);
    engine2.destroy();

    expect(dec.toString("utf8")).toBe("Секретная заметка");
  });
});

// ─────────────────────────────────────────────
// Восстановление по ручной соли (orphan vault)
// ─────────────────────────────────────────────

describe("AuthService — восстановление по ручной соли", () => {
  it("успешно восстанавливает orphan vault при правильной соли + пароле", async () => {
    // ── Шаг 1: создаём хранилище и шифруем тестовый файл ─────────────
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();
    const { engine } = await svc.authenticate("test-pwd", DEFAULT_SETTINGS, fn);
    const realSalt = lastSaved()!.saltHex!;
    const enc = engine.encryptBuffer(Buffer.from("data"));
    engine.destroy();

    // Сохраняем .enc на диск для верификации
    const fs = require("fs");
    const os = require("os");
    const nodePath = require("path");
    const tmpDir = fs.mkdtempSync(nodePath.join(os.tmpdir(), "sv-auth-"));
    const encPath = nodePath.join(tmpDir, "verify.enc");
    fs.writeFileSync(encPath, enc);

    try {
      // ── Шаг 2: симулируем потерю data.json — orphan settings ─────────
      const orphanSettings: PluginSettings = { ...DEFAULT_SETTINGS };
      const { fn: saveFn2, lastSaved: ls2 } = makeSaveFn();

      // ── Шаг 3: восстановление с ручной солью ─────────────────────────
      const result = await svc.authenticate("test-pwd", orphanSettings, saveFn2, {
        manualSaltHex: realSalt,
        verifyEncFileAbs: encPath,
      });

      expect(result.engine.isUnlocked()).toBe(true);
      expect(result.isFirstRun).toBe(false);

      // settings обновились — соль и verificationBlob сохранены
      const saved = ls2()!;
      expect(saved.saltHex).toBe(realSalt);
      expect(saved.verificationBlob).toBeTruthy();

      // Восстановленный engine может расшифровать оригинальный .enc
      const dec = result.engine.decryptBuffer(enc);
      expect(dec.toString("utf8")).toBe("data");
      result.engine.destroy();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("отклоняет неверную соль с PasswordError", async () => {
    const svc = new AuthService();
    const fakeOrphan: PluginSettings = { ...DEFAULT_SETTINGS };
    const fakeEnc = Buffer.from("a".repeat(60), "hex"); // не валидный .enc

    const fs = require("fs");
    const os = require("os");
    const nodePath = require("path");
    const tmpDir = fs.mkdtempSync(nodePath.join(os.tmpdir(), "sv-auth-"));
    const encPath = nodePath.join(tmpDir, "fake.enc");
    fs.writeFileSync(encPath, fakeEnc);

    try {
      const wrongSalt = "00".repeat(32);
      await expect(
        svc.authenticate("any-pwd", fakeOrphan, async () => {}, {
          manualSaltHex: wrongSalt,
          verifyEncFileAbs: encPath,
        })
      ).rejects.toThrow(PasswordError);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("отклоняет невалидный hex (не цифры/a-f, нечётная длина)", async () => {
    const svc = new AuthService();
    const settings: PluginSettings = { ...DEFAULT_SETTINGS };

    await expect(
      svc.authenticate("pwd", settings, async () => {}, { manualSaltHex: "xyz123" })
    ).rejects.toThrow(/hex-строкой/);

    await expect(
      svc.authenticate("pwd", settings, async () => {}, { manualSaltHex: "abc" })
    ).rejects.toThrow(/hex-строкой/);
  });

  it("в обычном flow с verificationBlob сверяет ручную соль через blob", async () => {
    // Создаём настоящие settings с verificationBlob
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();
    const { engine } = await svc.authenticate("real-pwd", DEFAULT_SETTINGS, fn);
    engine.destroy();

    const settings = lastSaved()!;
    const realSalt = settings.saltHex!;

    // Восстановление с ручной солью + правильным паролем — должно пройти через verificationBlob
    const { fn: fn2 } = makeSaveFn();
    const result = await svc.authenticate("real-pwd", settings, fn2, {
      manualSaltHex: realSalt,
    });
    expect(result.engine.isUnlocked()).toBe(true);
    result.engine.destroy();

    // Неверный пароль с правильной солью — отклоняется
    await expect(
      svc.authenticate("wrong-pwd", settings, async () => {}, { manualSaltHex: realSalt })
    ).rejects.toThrow(PasswordError);
  });
});
