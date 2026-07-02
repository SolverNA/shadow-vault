/**
 * Юнит-тесты для AuthService.
 * Obsidian API не нужен — тестируем чистую логику аутентификации.
 *
 * Соль не используется: ключ деривируется только из пароля.
 * Признак инициализированности хранилища — наличие verificationBlob.
 */

import { describe, it, expect, jest } from "@jest/globals";
import { AuthService, PasswordError, SettingsCorruptedError } from "../src/auth-service";
import { DEFAULT_SETTINGS, PluginSettings } from "../src/types";
import * as cryptoFactory from "../src/crypto/factory";
import { WebCryptoEngine } from "../src/web-crypto-engine";

/** Email для тестов — фиксированная соль деривации. */
const TEST_EMAIL = "test@vault.local";

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

describe("AuthService — первый запуск (verificationBlob === null)", () => {
  it("успешно инициализирует хранилище и возвращает разблокированный engine", async () => {
    const svc = new AuthService();
    const { fn } = makeSaveFn();

    const result = await svc.authenticate(TEST_EMAIL, "my-secure-password", DEFAULT_SETTINGS, fn);

    expect(result.isFirstRun).toBe(true);
    expect(result.engine.isUnlocked()).toBe(true);
    result.engine.destroy();
  });

  it("сохраняет verificationBlob, email и KDF-параметры в settings", async () => {
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();

    await svc.authenticate(TEST_EMAIL, "my-secure-password", DEFAULT_SETTINGS, fn);

    expect(fn).toHaveBeenCalledTimes(1);
    const saved = lastSaved()!;
    expect(saved.verificationBlob).toBeTruthy();
    // verificationBlob — hex-строка зашифрованного маркера длиной минимум 56 символов
    // (12 байт IV + 16 байт authTag + ≥0 байт ciphertext, всё в hex = ×2)
    expect(saved.verificationBlob!.length).toBeGreaterThanOrEqual(56);
    // Email НЕ секрет — сохраняется для автоподстановки при следующем входе.
    expect(saved.email).toBe(TEST_EMAIL);
    expect(saved.kdfIterations).toBe(600_000);
    expect(saved.formatVersion).toBe(2);
  });

  it("бросает PasswordError при пустом email", async () => {
    const svc = new AuthService();
    const { fn } = makeSaveFn();
    await expect(svc.authenticate("", "password", DEFAULT_SETTINGS, fn)).rejects.toThrow(PasswordError);
  });

  it("разный email → разный ключ (разная соль)", async () => {
    const svc1 = new AuthService();
    const { fn: f1, lastSaved: ls1 } = makeSaveFn();
    const r1 = await svc1.authenticate("a@vault.local", "same-pwd", DEFAULT_SETTINGS, f1);
    const enc = r1.engine.encryptBuffer(Buffer.from("data"));
    r1.engine.destroy();

    // Вход с тем же паролем, но другим email и сохранённым blob от первого —
    // должен провалиться (другая соль → другой ключ).
    const svc2 = new AuthService();
    const { fn: f2 } = makeSaveFn();
    await expect(
      svc2.authenticate("b@vault.local", "same-pwd", { ...ls1()!, email: "b@vault.local" }, f2)
    ).rejects.toThrow(PasswordError);
    void enc;
  });

  it("разные запуски с одним паролем → разные verificationBlob (случайный IV)", async () => {
    const svc = new AuthService();
    const { fn: fn1, lastSaved: ls1 } = makeSaveFn();
    const { fn: fn2, lastSaved: ls2 } = makeSaveFn();

    await svc.authenticate(TEST_EMAIL, "password", DEFAULT_SETTINGS, fn1);
    await svc.authenticate(TEST_EMAIL, "password", DEFAULT_SETTINGS, fn2);

    // Ключ одинаковый (соли нет), но IV случайный — blob'ы должны различаться
    expect(ls1()!.verificationBlob).not.toBe(ls2()!.verificationBlob);
  });

  it("одинаковый пароль → одинаковый ключ (детерминированность без соли)", async () => {
    const svc = new AuthService();
    const { fn: fn1, lastSaved: ls1 } = makeSaveFn();

    // Первый запуск создаёт хранилище
    const r1 = await svc.authenticate(TEST_EMAIL, "same-password", DEFAULT_SETTINGS, fn1);
    const enc = r1.engine.encryptBuffer(Buffer.from("test data"));
    r1.engine.destroy();

    // Второй "первый запуск" с тем же паролем — engine с тем же ключом
    // должен расшифровать данные первого
    const { fn: fn2 } = makeSaveFn();
    const r2 = await svc.authenticate(TEST_EMAIL, "same-password", DEFAULT_SETTINGS, fn2);
    const dec = r2.engine.decryptBuffer(enc);
    expect(dec.toString("utf8")).toBe("test data");
    r2.engine.destroy();
  });

  it("бросает PasswordError при пустом пароле", async () => {
    const svc = new AuthService();
    const { fn } = makeSaveFn();

    await expect(svc.authenticate(TEST_EMAIL, "", DEFAULT_SETTINGS, fn)).rejects.toThrow(PasswordError);
    await expect(svc.authenticate(TEST_EMAIL, "   ", DEFAULT_SETTINGS, fn)).rejects.toThrow(PasswordError);
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
    const result = await svc.authenticate(TEST_EMAIL, password, DEFAULT_SETTINGS, fn);
    result.engine.destroy();
    return lastSaved()!;
  }

  it("успешный вход с правильным паролем", async () => {
    const savedSettings = await initVault("correct-password");

    const svc = new AuthService();
    const { fn } = makeSaveFn();
    const result = await svc.authenticate(TEST_EMAIL, "correct-password", savedSettings, fn);

    expect(result.isFirstRun).toBe(false);
    expect(result.engine.isUnlocked()).toBe(true);
    result.engine.destroy();
  });

  it("не вызывает saveFn при повторном входе", async () => {
    const savedSettings = await initVault("password");

    const svc = new AuthService();
    const { fn } = makeSaveFn();
    const result = await svc.authenticate(TEST_EMAIL, "password", savedSettings, fn);
    result.engine.destroy();

    expect(fn).not.toHaveBeenCalled();
  });

  it("бросает PasswordError при неверном пароле", async () => {
    const savedSettings = await initVault("correct-password");

    const svc = new AuthService();
    const { fn } = makeSaveFn();

    await expect(
      svc.authenticate(TEST_EMAIL, "wrong-password", savedSettings, fn)
    ).rejects.toThrow(PasswordError);
  });

  it("после неверного пароля engine не утекает в памяти", async () => {
    const savedSettings = await initVault("correct-password");

    const svc = new AuthService();
    const { fn } = makeSaveFn();

    await expect(
      svc.authenticate(TEST_EMAIL, "wrong", savedSettings, fn)
    ).rejects.toThrow(PasswordError);
    // Если бы engine утёк — он бы остался в памяти в unlocked состоянии.
    // Проверяем косвенно: следующая попытка с правильным паролем должна работать нормально.
    const result = await svc.authenticate(TEST_EMAIL, "correct-password", savedSettings, fn);
    expect(result.engine.isUnlocked()).toBe(true);
    result.engine.destroy();
  });

  it("бросает SettingsCorruptedError если verificationBlob отсутствует но это не первый запуск", async () => {
    // Симулируем повреждённые настройки: блоб null, но мы вызываем verifyPassword напрямую
    // (это путь ChangePassword — не должен молча создавать новое хранилище)
    const corruptedSettings: PluginSettings = { ...DEFAULT_SETTINGS, verificationBlob: null };

    await expect(
      AuthService.verifyPassword(TEST_EMAIL, "password", corruptedSettings)
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
      svc.authenticate(TEST_EMAIL, "password", corruptedSettings, fn)
    ).rejects.toThrow(PasswordError);
  });

  it("бросает SettingsCorruptedError если verificationBlob — не hex (битый data.json)", async () => {
    const savedSettings = await initVault("password");
    const corruptedSettings: PluginSettings = {
      ...savedSettings,
      verificationBlob: "zz-не-hex-мусор!!",
    };

    // Раньше битый hex тихо превращался в мусорные байты (NaN → 0) и падал
    // как «неверный пароль». Теперь — явная ошибка формата настроек.
    await expect(
      AuthService.verifyPassword(TEST_EMAIL, "password", corruptedSettings)
    ).rejects.toThrow(SettingsCorruptedError);
  });

  it("бросает SettingsCorruptedError если verificationBlob — hex нечётной длины", async () => {
    const savedSettings = await initVault("password");
    const corruptedSettings: PluginSettings = {
      ...savedSettings,
      verificationBlob: savedSettings.verificationBlob!.slice(0, -1), // обрезан на 1 символ
    };

    await expect(
      AuthService.verifyPassword(TEST_EMAIL, "password", corruptedSettings)
    ).rejects.toThrow(SettingsCorruptedError);
  });
});

// ─────────────────────────────────────────────
// Сквозной сценарий: создание → повторный вход
// ─────────────────────────────────────────────

describe("AuthService — сквозные сценарии", () => {
  it("engine из первого запуска может шифровать данные, которые расшифрует engine повторного входа", async () => {
    const svc1 = new AuthService();
    const { fn, lastSaved } = makeSaveFn();

    // Первый запуск — создаём хранилище
    const { engine: engine1 } = await svc1.authenticate(TEST_EMAIL, "vault-password", DEFAULT_SETTINGS, fn);
    const enc = engine1.encryptBuffer(Buffer.from("Секретная заметка"));
    engine1.destroy();

    // Повторный вход с тем же паролем
    const svc2 = new AuthService();
    const { fn: fn2 } = makeSaveFn();
    const { engine: engine2 } = await svc2.authenticate(TEST_EMAIL, "vault-password", lastSaved()!, fn2);
    const dec = engine2.decryptBuffer(enc);
    engine2.destroy();

    expect(dec.toString("utf8")).toBe("Секретная заметка");
  });

  it("recovery без data.json: тот же пароль на чистых настройках восстанавливает доступ к старым .enc", async () => {
    // Создаём vault, шифруем данные
    const svc1 = new AuthService();
    const { fn: fn1, lastSaved: ls1 } = makeSaveFn();
    const { engine: engine1 } = await svc1.authenticate(TEST_EMAIL, "user-password", DEFAULT_SETTINGS, fn1);
    const enc = engine1.encryptBuffer(Buffer.from("data from old vault"));
    engine1.destroy();

    // Сохранённые настройки — храним их рядом для подтверждения, что blob изменился
    const oldBlob = ls1()!.verificationBlob;

    // Симулируем потерю data.json: запускаем "первый запуск" заново
    const svc2 = new AuthService();
    const { fn: fn2, lastSaved: ls2 } = makeSaveFn();
    const { engine: engine2, isFirstRun } = await svc2.authenticate(
      TEST_EMAIL, "user-password", DEFAULT_SETTINGS, fn2
    );

    expect(isFirstRun).toBe(true);
    // Новый blob — другой (случайный IV), но ключ тот же → старые .enc расшифровываются
    expect(ls2()!.verificationBlob).not.toBe(oldBlob);

    const dec = engine2.decryptBuffer(enc);
    expect(dec.toString("utf8")).toBe("data from old vault");
    engine2.destroy();
  });
});

// ─────────────────────────────────────────────
// Mobile: окружение без глобального Buffer
// ─────────────────────────────────────────────

describe("AuthService — mobile (WebCryptoEngine, без глобального Buffer)", () => {
  it("первый запуск и повторный вход проходят без Buffer (регрессия ReferenceError на mobile)", async () => {
    // Симулируем mobile: фабрика отдаёт WebCryptoEngine, глобального Buffer нет
    const spy = jest
      .spyOn(cryptoFactory, "createCryptoEngine")
      .mockImplementation(() => new WebCryptoEngine());
    const g = globalThis as { Buffer?: unknown };
    const savedBuffer = g.Buffer;
    delete g.Buffer;

    try {
      // Первый запуск (онбординг) — раньше падал с "Buffer is not defined"
      const svc = new AuthService();
      const { fn, lastSaved } = makeSaveFn();
      const result = await svc.authenticate(TEST_EMAIL, "mobile-password", DEFAULT_SETTINGS, fn);

      expect(result.isFirstRun).toBe(true);
      expect(result.engine.isUnlocked()).toBe(true);
      expect(lastSaved()!.verificationBlob).toBeTruthy();
      result.engine.destroy();

      // Повторный вход по сохранённому verificationBlob — тоже без Buffer
      const svc2 = new AuthService();
      const { fn: fn2 } = makeSaveFn();
      const result2 = await svc2.authenticate(TEST_EMAIL, "mobile-password", lastSaved()!, fn2);
      expect(result2.isFirstRun).toBe(false);
      result2.engine.destroy();
    } finally {
      g.Buffer = savedBuffer;
      spy.mockRestore();
    }
  });
});

// ─────────────────────────────────────────────
// Orphan-защита: firstRunValidator против «отравления» verificationBlob
// ─────────────────────────────────────────────

describe("AuthService — защита от отравления verificationBlob (orphan-сценарий)", () => {
  /**
   * Готовит «осиротевшее» хранилище: шифрует образец правильным паролем
   * (это наш .enc на диске), data.json считается утерянным (blob = null).
   */
  async function makeOrphanEnc(correctPassword: string): Promise<Uint8Array> {
    const svc = new AuthService();
    const { fn } = makeSaveFn();
    const { engine } = await svc.authenticate(TEST_EMAIL, correctPassword, DEFAULT_SETTINGS, fn);
    const enc = engine.encryptBuffer(Buffer.from("содержимое старой заметки"));
    engine.destroy();
    return new Uint8Array(enc);
  }

  /**
   * Валидатор как в main.ts: trial-decrypt существующего .enc деривированным
   * движком. true — расшифровался, false — нет (значит пароль неверный).
   */
  function makeValidator(encSample: Uint8Array) {
    return async (engine: { decryptBuffer(b: Uint8Array): unknown }): Promise<boolean | null> => {
      try {
        await Promise.resolve(engine.decryptBuffer(encSample));
        return true;
      } catch {
        return false;
      }
    };
  }

  it("есть .enc + нет blob + НЕВЕРНЫЙ пароль → PasswordError, blob НЕ записан", async () => {
    const encSample = await makeOrphanEnc("correct-password");

    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();

    await expect(
      svc.authenticate(TEST_EMAIL, "wrong-password", DEFAULT_SETTINGS, fn, makeValidator(encSample))
    ).rejects.toThrow(PasswordError);

    // Главное: настройки НЕ сохранены — «отравленный» blob не записан.
    expect(fn).not.toHaveBeenCalled();
    expect(lastSaved()).toBeNull();
  });

  it("есть .enc + нет blob + ВЕРНЫЙ пароль → blob записан, вход успешен", async () => {
    const encSample = await makeOrphanEnc("correct-password");

    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();

    const result = await svc.authenticate(
      TEST_EMAIL, "correct-password", DEFAULT_SETTINGS, fn, makeValidator(encSample)
    );

    expect(result.isFirstRun).toBe(true);
    expect(result.engine.isUnlocked()).toBe(true);
    expect(lastSaved()!.verificationBlob).toBeTruthy();

    // И ключ действительно расшифровывает старые данные.
    const dec = result.engine.decryptBuffer(encSample);
    expect(Buffer.from(dec).toString("utf8")).toBe("содержимое старой заметки");
    result.engine.destroy();
  });

  it("настоящий first-run (валидатор вернул null — .enc нет) → blob создаётся как раньше", async () => {
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();
    const validator = jest.fn(async () => null as boolean | null);

    const result = await svc.authenticate(
      TEST_EMAIL, "brand-new-password", DEFAULT_SETTINGS, fn, validator
    );

    expect(validator).toHaveBeenCalledTimes(1);
    expect(result.isFirstRun).toBe(true);
    expect(lastSaved()!.verificationBlob).toBeTruthy();
    expect(lastSaved()!.email).toBe(TEST_EMAIL);
    result.engine.destroy();
  });

  it("после отклонения неверного пароля ВЕРНЫЙ пароль по-прежнему проходит (нет lockout)", async () => {
    const encSample = await makeOrphanEnc("correct-password");
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();

    await expect(
      svc.authenticate(TEST_EMAIL, "typo-password", DEFAULT_SETTINGS, fn, makeValidator(encSample))
    ).rejects.toThrow(PasswordError);

    // Повторная попытка с правильным паролем — успех (blob не был отравлен).
    const result = await svc.authenticate(
      TEST_EMAIL, "correct-password", DEFAULT_SETTINGS, fn, makeValidator(encSample)
    );
    expect(result.isFirstRun).toBe(true);
    expect(lastSaved()!.verificationBlob).toBeTruthy();
    result.engine.destroy();
  });

  it("без валидатора (не внедрён) поведение прежнее — blob создаётся сразу", async () => {
    const svc = new AuthService();
    const { fn, lastSaved } = makeSaveFn();
    const result = await svc.authenticate(TEST_EMAIL, "any-password", DEFAULT_SETTINGS, fn);
    expect(result.isFirstRun).toBe(true);
    expect(lastSaved()!.verificationBlob).toBeTruthy();
    result.engine.destroy();
  });
});
