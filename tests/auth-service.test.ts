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
