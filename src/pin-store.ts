/**
 * PinStore — локальный (device-local) быстрый вход по PIN через key-wrapping.
 *
 * БЕЗОПАСНОСТЬ / АРХИТЕКТУРА:
 *   - PIN НЕ деривирует мастер-ключ напрямую. Вместо этого:
 *       pinKey       = PBKDF2(pin, deviceSalt, iterations, SHA-512) → 32 байта
 *       wrappedMaster = AES-GCM(masterKey, pinKey)  (контейнер v2)
 *     Зная masterKey, PIN не восстанавливается (PBKDF2 односторонний).
 *
 *   - ЧЕСТНАЯ ОЦЕНКА СТОЙКОСТИ: фактическая стойкость wrappedMaster равна
 *     ЭНТРОПИИ PIN, а не стойкости мастер-пароля. wrappedMaster + deviceSalt
 *     лежат в localStorage, лимит попыток — чисто клиентский (сам счётчик
 *     тоже в localStorage). Атакующий, скопировавший данные устройства,
 *     перебирает PIN офлайн без всяких лимитов: пространство 4–8 цифр — это
 *     10^4–10^8 вариантов, и даже с сотнями тысяч итераций PBKDF2 такой
 *     перебор тривиален на GPU (часы, не годы). Итерации лишь удорожают
 *     перебор, но НЕ делают его невозможным.
 *     Поэтому PIN — защита от «подглядывания через плечо» и случайного
 *     доступа (взял телефон со стола), НЕ от атакующего с полным доступом
 *     к устройству/его файлам. Кому важна эта модель угроз — PIN включать
 *     не следует, только полный пароль.
 *
 *   - wrappedMaster + deviceSalt + счётчик попыток хранятся ТОЛЬКО ЛОКАЛЬНО
 *     в window.localStorage. localStorage — per-device, НЕ синхронизируется
 *     ни через Obsidian Sync, ни через облако/git (это не файл vault).
 *     Эти данные НИКОГДА не попадают в data.json.
 *   - Пароль остаётся корнем доверия: PIN — лишь локальное удобство. Пароль
 *     всегда работает; при превышении лимита попыток PIN-данные стираются и
 *     требуется полный пароль.
 *
 * Точка расширения для биометрии: биометрия (если когда-либо будет доступна
 * в песочнице Obsidian) разблокирует ровно тот же wrappedMaster — т.е. тот же
 * механизм key-wrapping, лишь с другим способом получения unlock-фактора.
 *
 * Кросс-платформенность: модуль НЕ импортирует node-модули. PBKDF2/AES-GCM/
 * randomBytes идут через crypto/platform (getSubtle / randomBytes), которые
 * работают и на desktop (Node webcrypto), и на mobile (браузерный crypto).
 */

import { getSubtle, randomBytes } from "./crypto/platform";
import { KEY_LENGTH, IV_LENGTH, GCM_TAG_LENGTH } from "./crypto/constants";
import { writeContainer, parseContainer } from "./crypto/format";
import { bytesToHex, hexToBytes } from "./hex";

/** Префикс ключей localStorage — уникален для устройства/плагина. */
const LS_PREFIX = "shadow-vault:pin:";
const LS_WRAPPED = LS_PREFIX + "wrapped";
const LS_DEVICE_SALT = LS_PREFIX + "deviceSalt";
const LS_ATTEMPTS = LS_PREFIX + "attempts";
const LS_ITERATIONS = LS_PREFIX + "iterations";
const LS_BIOMETRIC = LS_PREFIX + "biometric";

/**
 * Итерации PBKDF2 для НОВЫХ PIN-blob'ов. Выровнено с мастер-паролем (600k,
 * SHA-512): setupPin/unlockWithPin выполняются раз за сессию, задержка
 * ~0.5–2 сек на mobile приемлема, а стоимость офлайн-перебора растёт втрое.
 * (Перебор всё равно возможен — см. шапку файла; итерации лишь удорожают его.)
 */
export const PIN_KDF_ITERATIONS = 600_000;
/**
 * Итерации, которыми писались старые blob'ы ДО того, как число итераций
 * стало сохраняться в localStorage (LS_ITERATIONS). Если поле отсутствует —
 * blob создан старой версией и читается с этим значением. НЕ МЕНЯТЬ.
 */
export const PIN_KDF_ITERATIONS_LEGACY = 200_000;
/** Длина случайной соли устройства. */
export const DEVICE_SALT_LENGTH = 16;
/** Лимит неверных попыток PIN до сброса PIN-данных. */
export const PIN_MAX_ATTEMPTS = 5;

const utf8 = new TextEncoder();

/** Абстракция хранилища (для тестов можно подставить fake). */
export interface DeviceStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** Доступ к window.localStorage; null если недоступно (например, в чистом Node-тесте). */
function defaultStore(): DeviceStore | null {
  const g = globalThis as unknown as { localStorage?: DeviceStore };
  return g.localStorage ?? null;
}

/**
 * Деривирует pinKey из PIN + deviceSalt (PBKDF2-SHA512).
 * Промежуточные сырые байты pinKey зачищаются сразу после импорта в
 * non-extractable CryptoKey.
 */
async function derivePinKey(
  pin: string,
  deviceSalt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  const subtle = getSubtle();
  const material = await subtle.importKey(
    "raw",
    utf8.encode(pin),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = new Uint8Array(
    await subtle.deriveBits(
      { name: "PBKDF2", salt: deviceSalt, iterations, hash: "SHA-512" },
      material,
      KEY_LENGTH * 8
    )
  );
  try {
    return await subtle.importKey(
      "raw",
      bits,
      { name: "AES-GCM", length: KEY_LENGTH * 8 },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    bits.fill(0);
  }
}

/** Ошибки PIN-входа. */
export class PinError extends Error {
  readonly kind = "PinError" as const;
  constructor(message: string, readonly attemptsLeft: number) {
    super(message);
    this.name = "PinError";
  }
}
export class PinLockoutError extends Error {
  readonly kind = "PinLockoutError" as const;
  constructor(message: string) {
    super(message);
    this.name = "PinLockoutError";
  }
}

export class PinStore {
  constructor(private readonly store: DeviceStore | null = defaultStore()) {}

  /** true, если на этом устройстве настроен PIN-вход. */
  isPinSet(): boolean {
    return !!this.store && this.store.getItem(LS_WRAPPED) !== null;
  }

  /**
   * Включает PIN-вход: оборачивает masterKey ключом из PIN и сохраняет
   * wrappedMaster+deviceSalt локально. masterKey передаётся как сырые 32 байта.
   *
   * ВЛАДЕНИЕ: masterKey остаётся у вызывающего — метод только читает байты
   * (шифрует их в wrappedMaster); вызывающий обязан зачистить свой буфер
   * (fill(0)) после вызова. Новые blob'ы пишутся с PIN_KDF_ITERATIONS,
   * число итераций сохраняется рядом (LS_ITERATIONS) для совместимости.
   */
  async enablePin(pin: string, masterKey: Uint8Array): Promise<void> {
    if (!this.store) {
      throw new PinLockoutError(
        "Локальное хранилище недоступно — PIN на этом устройстве не поддерживается."
      );
    }
    if (masterKey.length !== KEY_LENGTH) {
      throw new Error("[PinStore] masterKey должен быть 32 байта");
    }
    const deviceSalt = randomBytes(DEVICE_SALT_LENGTH);
    const pinKey = await derivePinKey(pin, deviceSalt, PIN_KDF_ITERATIONS);

    const iv = randomBytes(IV_LENGTH);
    const subtle = getSubtle();
    const ctWithTag = await subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH * 8 },
      pinKey,
      masterKey
    );
    const wrapped = writeContainer(iv, new Uint8Array(ctWithTag));

    this.store.setItem(LS_WRAPPED, bytesToHex(wrapped));
    this.store.setItem(LS_DEVICE_SALT, bytesToHex(deviceSalt));
    this.store.setItem(LS_ITERATIONS, String(PIN_KDF_ITERATIONS));
    this.store.setItem(LS_ATTEMPTS, "0");
  }

  /**
   * Разблокирует по PIN: разворачивает wrappedMaster → сырой masterKey.
   * Считает неверные попытки; при превышении лимита стирает PIN-данные.
   *
   * Совместимость: число итераций PBKDF2 читается из LS_ITERATIONS; если
   * поле отсутствует (blob старой версии) — используется легаси-значение
   * PIN_KDF_ITERATIONS_LEGACY, которым такие blob'ы были записаны.
   *
   * ВЛАДЕНИЕ: возвращаемый сырой masterKey переходит вызывающему — он ОБЯЗАН
   * зачистить его (fill(0)), как только ключ загружен в движок/обёрнут заново.
   *
   * @throws PinError       при неверном PIN (с числом оставшихся попыток)
   * @throws PinLockoutError если PIN не настроен или лимит исчерпан
   */
  async unlockWithPin(pin: string): Promise<Uint8Array> {
    if (!this.store || !this.isPinSet()) {
      throw new PinLockoutError("PIN не настроен на этом устройстве.");
    }

    const wrappedHex = this.store.getItem(LS_WRAPPED)!;
    const saltHex = this.store.getItem(LS_DEVICE_SALT)!;
    // Blob без поля итераций — записан старой версией с легаси-числом.
    const storedIterations = this.store.getItem(LS_ITERATIONS);
    const parsedIterations = storedIterations === null ? NaN : parseInt(storedIterations, 10);
    const iterations = Number.isFinite(parsedIterations) && parsedIterations > 0
      ? parsedIterations
      : PIN_KDF_ITERATIONS_LEGACY;

    // Битый hex в localStorage (повреждённые PIN-данные) — не «неверный PIN»,
    // а необратимая порча: разблокировать таким wrappedMaster нельзя никогда.
    // Стираем PIN-данные и явно отправляем пользователя на вход по паролю.
    let deviceSalt: Uint8Array;
    let container: Uint8Array;
    try {
      deviceSalt = hexToBytes(saltHex);
      container = hexToBytes(wrappedHex);
    } catch {
      this.clearPin();
      throw new PinLockoutError(
        "PIN-данные на этом устройстве повреждены. PIN сброшен — войдите по паролю."
      );
    }

    const pinKey = await derivePinKey(pin, deviceSalt, iterations);
    const { iv, body } = parseContainer(container);

    try {
      const subtle = getSubtle();
      const raw = await subtle.decrypt(
        { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH * 8 },
        pinKey,
        body
      );
      const master = new Uint8Array(raw);
      // Успех — сбрасываем счётчик попыток.
      this.store.setItem(LS_ATTEMPTS, "0");
      return master;
    } catch {
      // Неверный PIN → AES-GCM auth tag mismatch.
      const attempts = this.bumpAttempts();
      const left = PIN_MAX_ATTEMPTS - attempts;
      if (left <= 0) {
        this.clearPin();
        throw new PinLockoutError(
          "Слишком много неверных попыток PIN. PIN сброшен — войдите по паролю."
        );
      }
      throw new PinError(`Неверный PIN. Осталось попыток: ${left}.`, left);
    }
  }

  /** Текущее число неверных попыток. */
  getAttempts(): number {
    if (!this.store) return 0;
    return parseInt(this.store.getItem(LS_ATTEMPTS) ?? "0", 10);
  }

  private bumpAttempts(): number {
    const next = this.getAttempts() + 1;
    this.store?.setItem(LS_ATTEMPTS, String(next));
    return next;
  }

  /** Полностью удаляет PIN-данные с устройства. */
  clearPin(): void {
    if (!this.store) return;
    this.store.removeItem(LS_WRAPPED);
    this.store.removeItem(LS_DEVICE_SALT);
    this.store.removeItem(LS_ATTEMPTS);
    this.store.removeItem(LS_ITERATIONS);
  }

  // ── Биометрия (точка расширения) ──────────────────────────────────────
  // Реалистично: плагин Obsidian в песочнице НЕ имеет прямого доступа к
  // нативному FaceID/Touch ID, поэтому это пока флаг-заглушка. Когда/если
  // появится доступный web/Obsidian API — биометрия разблокирует тот же
  // wrappedMaster (тот же механизм key-wrapping, что и PIN).

  /** Поддерживается ли биометрия на этом устройстве (сейчас всегда false). */
  isBiometricSupported(): boolean {
    // TODO(биометрия): нет доступного нативного API в песочнице Obsidian.
    return false;
  }

  /** Включена ли биометрия пользователем (флаг хранится device-local). */
  isBiometricEnabled(): boolean {
    return !!this.store && this.store.getItem(LS_BIOMETRIC) === "1";
  }

  setBiometricEnabled(on: boolean): void {
    if (!this.store) return;
    if (on) this.store.setItem(LS_BIOMETRIC, "1");
    else this.store.removeItem(LS_BIOMETRIC);
  }
}
