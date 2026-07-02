/**
 * Тесты PinStore — быстрый локальный вход по PIN через key-wrapping.
 *
 * Проверяем:
 *   - round-trip: PIN оборачивает masterKey и разворачивает его обратно;
 *   - неверный PIN не раскрывает ключ и считает попытки;
 *   - лимит попыток сбрасывает PIN-данные;
 *   - данные хранятся в переданном DeviceStore (device-local), НЕ в data.json.
 */

import { describe, it, expect, beforeEach } from "@jest/globals";
import {
  PinStore,
  PinError,
  PinLockoutError,
  PIN_MAX_ATTEMPTS,
  DeviceStore,
} from "../src/pin-store";
import { randomBytes } from "../src/crypto/platform";
import { deriveMasterKey } from "../src/crypto/key-derivation";
import { NodeCryptoEngine } from "../src/crypto-engine";

/** In-memory реализация DeviceStore — имитирует window.localStorage. */
class FakeStore implements DeviceStore {
  readonly map = new Map<string, string>();
  getItem(k: string): string | null { return this.map.has(k) ? this.map.get(k)! : null; }
  setItem(k: string, v: string): void { this.map.set(k, v); }
  removeItem(k: string): void { this.map.delete(k); }
}

const MASTER = (() => randomBytes(32))();

describe("PinStore — round-trip", () => {
  let store: FakeStore;
  let pin: PinStore;

  beforeEach(() => {
    store = new FakeStore();
    pin = new PinStore(store);
  });

  it("enablePin → unlockWithPin возвращает исходный masterKey", async () => {
    await pin.enablePin("1234", MASTER);
    expect(pin.isPinSet()).toBe(true);

    const recovered = await pin.unlockWithPin("1234");
    expect(Buffer.from(recovered).equals(Buffer.from(MASTER))).toBe(true);
  });

  it("неверный PIN бросает PinError и не раскрывает ключ", async () => {
    await pin.enablePin("1234", MASTER);
    await expect(pin.unlockWithPin("0000")).rejects.toThrow(PinError);
  });

  it("успешный вход сбрасывает счётчик попыток", async () => {
    await pin.enablePin("1234", MASTER);
    await expect(pin.unlockWithPin("0000")).rejects.toThrow(PinError);
    expect(pin.getAttempts()).toBe(1);
    await pin.unlockWithPin("1234");
    expect(pin.getAttempts()).toBe(0);
  });
});

describe("PinStore — лимит попыток", () => {
  it(`после ${PIN_MAX_ATTEMPTS} неверных попыток PIN-данные стираются`, async () => {
    const store = new FakeStore();
    const pin = new PinStore(store);
    await pin.enablePin("4321", MASTER);

    // PIN_MAX_ATTEMPTS-1 попыток → PinError, последняя → PinLockoutError
    for (let i = 0; i < PIN_MAX_ATTEMPTS - 1; i++) {
      await expect(pin.unlockWithPin("0000")).rejects.toThrow(PinError);
    }
    await expect(pin.unlockWithPin("0000")).rejects.toThrow(PinLockoutError);

    // PIN сброшен — больше не настроен, дальнейший вход по PIN невозможен.
    expect(pin.isPinSet()).toBe(false);
    await expect(pin.unlockWithPin("4321")).rejects.toThrow(PinLockoutError);
  });

  it("attemptsLeft в PinError убывает", async () => {
    const store = new FakeStore();
    const pin = new PinStore(store);
    await pin.enablePin("1111", MASTER);
    try {
      await pin.unlockWithPin("9999");
    } catch (e) {
      expect(e).toBeInstanceOf(PinError);
      expect((e as PinError).attemptsLeft).toBe(PIN_MAX_ATTEMPTS - 1);
    }
  });
});

describe("PinStore — device-local хранение", () => {
  it("wrapped key и deviceSalt лежат ТОЛЬКО в DeviceStore (не в объекте настроек)", async () => {
    const store = new FakeStore();
    const pin = new PinStore(store);
    await pin.enablePin("2468", MASTER);

    // Все ключи имеют device-local префикс и реально записаны в store.
    const keys = [...store.map.keys()];
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.every((k) => k.startsWith("shadow-vault:pin:"))).toBe(true);

    // Ни одно значение не равно сырому masterKey (он именно обёрнут, не открыт).
    const masterHex = Buffer.from(MASTER).toString("hex");
    for (const v of store.map.values()) {
      expect(v).not.toContain(masterHex);
    }
  });

  it("clearPin удаляет все device-local данные", async () => {
    const store = new FakeStore();
    const pin = new PinStore(store);
    await pin.enablePin("1357", MASTER);
    expect(store.map.size).toBeGreaterThan(0);
    pin.clearPin();
    expect(store.map.size).toBe(0);
    expect(pin.isPinSet()).toBe(false);
  });

  it("без DeviceStore (null) PIN не поддерживается, enablePin бросает", async () => {
    const pin = new PinStore(null);
    expect(pin.isPinSet()).toBe(false);
    await expect(pin.enablePin("1234", MASTER)).rejects.toThrow(PinLockoutError);
  });
});

describe("PinStore — повреждённые PIN-данные (битый hex в localStorage)", () => {
  it("битый wrappedMaster → PinLockoutError и сброс PIN (не «неверный PIN»)", async () => {
    const store = new FakeStore();
    const pin = new PinStore(store);
    await pin.enablePin("1234", MASTER);

    // Симулируем порчу localStorage: не-hex мусор вместо wrapped-контейнера.
    store.map.set("shadow-vault:pin:wrapped", "это-не-hex!!");

    await expect(pin.unlockWithPin("1234")).rejects.toThrow(PinLockoutError);
    // Повреждённые данные никогда не разблокируются — они стёрты.
    expect(pin.isPinSet()).toBe(false);
  });

  it("битый deviceSalt (hex нечётной длины) → PinLockoutError и сброс PIN", async () => {
    const store = new FakeStore();
    const pin = new PinStore(store);
    await pin.enablePin("1234", MASTER);

    const salt = store.map.get("shadow-vault:pin:deviceSalt")!;
    store.map.set("shadow-vault:pin:deviceSalt", salt.slice(0, -1)); // обрезан на 1 символ

    await expect(pin.unlockWithPin("1234")).rejects.toThrow(PinLockoutError);
    expect(pin.isPinSet()).toBe(false);
  });
});

describe("PinStore — интеграция с движком (вход по PIN)", () => {
  it("masterKey из deriveMasterKey, обёрнутый PIN, разворачивается и движок шифрует/расшифровывает", async () => {
    const email = "user@vault.local";
    const password = "real-vault-password";
    const master = await deriveMasterKey(email, password);

    const store = new FakeStore();
    const pin = new PinStore(store);
    await pin.enablePin("5678", master);

    // Вход по PIN: разворачиваем ключ и загружаем в движок напрямую.
    const recovered = await pin.unlockWithPin("5678");
    const engine = new NodeCryptoEngine();
    engine.loadRawKey(recovered);
    expect(engine.isUnlocked()).toBe(true);

    // Тот же ключ, что у обычного входа по паролю → данные взаимно совместимы.
    const refEngine = new NodeCryptoEngine();
    await refEngine.deriveKey(email, password);
    const enc = refEngine.encryptBuffer(Buffer.from("secret note"));
    const dec = engine.decryptBuffer(enc);
    expect(dec.toString("utf8")).toBe("secret note");

    engine.destroy();
    refEngine.destroy();
  });
});

describe("PinStore — биометрия (заглушка)", () => {
  it("биометрия не поддерживается, флаг хранится device-local", () => {
    const store = new FakeStore();
    const pin = new PinStore(store);
    expect(pin.isBiometricSupported()).toBe(false);
    expect(pin.isBiometricEnabled()).toBe(false);
    pin.setBiometricEnabled(true);
    expect(pin.isBiometricEnabled()).toBe(true);
  });
});
