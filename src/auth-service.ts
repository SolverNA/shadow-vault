/**
 * AuthService — чистая бизнес-логика аутентификации без зависимости от Obsidian API.
 * Тестируется в изоляции (Node.js), не требует моков UI.
 *
 * Ответственность:
 *   - Определить, первый ли это запуск (нет verificationBlob в настройках).
 *   - При первом запуске: деривировать ключ, сохранить верификационный блоб.
 *   - При повторном запуске: проверить пароль через верификационный блоб.
 *   - Вернуть готовый CryptoEngine с загруженным ключом.
 *
 * Соль не используется — ключ зависит только от пароля, см. CryptoEngine.
 */

import { createCryptoEngine, AnyCryptoEngine } from "./crypto/factory";
import { PBKDF2_ITERATIONS, FORMAT_VERSION } from "./crypto/constants";
import { bytesToHex, hexToBytes } from "./hex";
import {
  PluginSettings,
  VERIFICATION_PLAINTEXT,
} from "./types";

export type SaveSettingsFn = (settings: PluginSettings) => Promise<void>;

/** Приводит результат encryptBuffer (Buffer | ArrayBuffer) к Uint8Array. */
function toBytes(x: unknown): Uint8Array {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  throw new Error("[AuthService] неподдерживаемый результат движка");
}

export interface AuthResult {
  /**
   * Движок с загруженным ключом. На десктопе — NodeCryptoEngine, на мобильных —
   * WebCryptoEngine (выбор делает фабрика по платформе). main.ts на десктопе
   * использует его напрямую, на мобильных пересоздаёт WebCryptoEngine из пароля.
   */
  engine: AnyCryptoEngine;
  /**
   * Пароль для инициализации WebCryptoEngine на мобильных.
   * null при входе по PIN (пароль не вводился) — в этом случае mobile-путь
   * должен использовать rawKey вместо повторной деривации из пароля.
   */
  password: string | null;
  /** Email, использованный при деривации (нужен mobile-пути для повторной деривации) */
  email: string;
  /**
   * Сырой мастер-ключ (32 байта). Заполняется при входе по PIN, чтобы
   * mobile-путь мог загрузить ключ напрямую (loadRawKey) без пароля.
   */
  rawKey?: Uint8Array;
  /** true если это был первый запуск и настройки уже сохранены */
  isFirstRun: boolean;
}

export class AuthService {
  /**
   * Основной метод аутентификации.
   *
   * Логика:
   *   1. Если verificationBlob в настройках null → первый запуск.
   *      Деривируем ключ, создаём верификационный блоб, сохраняем настройки.
   *   2. Если verificationBlob есть → повторный запуск.
   *      Деривируем ключ, пробуем расшифровать verificationBlob.
   *      Если не вышло → бросаем PasswordError (неверный пароль).
   *
   * @param password   Пароль, введённый пользователем
   * @param settings   Текущие настройки плагина (из data.json)
   * @param saveFn     Функция сохранения настроек (внедряется извне для тестируемости)
   * @returns          AuthResult с готовым engine и флагом isFirstRun
   */
  async authenticate(
    email: string,
    password: string,
    settings: PluginSettings,
    saveFn: SaveSettingsFn
  ): Promise<AuthResult> {
    if (!email.trim()) {
      throw new PasswordError("Email не может быть пустым.");
    }
    if (!password.trim()) {
      throw new PasswordError("Пароль не может быть пустым.");
    }

    const isFirstRun = settings.verificationBlob === null;

    if (isFirstRun) {
      // ── Первый запуск: создаём хранилище ──────────────────────────────────
      // Фабрика выбирает движок по платформе (Node на десктопе, Web на mobile).
      // Формат v2 идентичен на обеих платформах, поэтому verificationBlob
      // кросс-платформенно совместим. Соль деривируется из email.
      const engine = createCryptoEngine();
      await engine.deriveKey(email, password);

      // Шифруем маркер верификации — чтобы при следующем входе можно было
      // проверить пароль, не расшифровывая реальные файлы
      const verificationBytes = toBytes(
        await Promise.resolve(
          engine.encryptBuffer(Buffer.from(VERIFICATION_PLAINTEXT, "utf8") as Uint8Array)
        )
      );

      const updatedSettings: PluginSettings = {
        ...settings,
        verificationBlob: bytesToHex(verificationBytes),
        // Email НЕ секрет — сохраняем, чтобы при следующем входе подставить.
        email: email.trim(),
        kdfIterations: PBKDF2_ITERATIONS,
        formatVersion: FORMAT_VERSION,
      };

      await saveFn(updatedSettings);
      return { engine, password, email: email.trim(), isFirstRun: true };
    }

    // ── Повторный запуск: проверяем пароль ────────────────────────────────
    // Email берём из сохранённых настроек (пользователь его не меняет на входе).
    const effectiveEmail = settings.email || email.trim();
    const verifiedEngine = await AuthService.verifyPassword(effectiveEmail, password, settings);
    return { engine: verifiedEngine, password, email: effectiveEmail, isFirstRun: false };
  }

  /**
   * Деривирует ключ и проверяет его корректность через verificationBlob.
   *
   * Используется и в обычной аутентификации, и в смене пароля
   * (чтобы независимо от активной сессии убедиться, что старый пароль верен).
   *
   * @param email    email (если пусто — берётся из settings.email)
   * @param password проверяемый пароль
   * @returns CryptoEngine с загруженным ключом (вызывающий обязан destroy())
   * @throws  PasswordError если пароль неверный
   * @throws  SettingsCorruptedError если verificationBlob отсутствует
   */
  static async verifyPassword(
    email: string,
    password: string,
    settings: PluginSettings
  ): Promise<AnyCryptoEngine> {
    if (!settings.verificationBlob) {
      throw new SettingsCorruptedError(
        "Файл настроек повреждён: verificationBlob отсутствует. " +
        "Восстановите data.json из резервной копии."
      );
    }

    const engine = createCryptoEngine();
    const effectiveEmail = email || settings.email;
    await engine.deriveKey(effectiveEmail, password);

    try {
      const decryptedBytes = toBytes(
        await Promise.resolve(
          engine.decryptBuffer(hexToBytes(settings.verificationBlob))
        )
      );
      const decryptedText = new TextDecoder().decode(decryptedBytes);
      if (decryptedText !== VERIFICATION_PLAINTEXT) {
        // Технически невозможно при корректном AES-GCM, но перестрахуемся
        engine.destroy();
        throw new PasswordError("Верификация не прошла: неверный пароль.");
      }
    } catch (err) {
      engine.destroy();
      if (err instanceof PasswordError) throw err;
      // CryptoEngine бросил ошибку Auth Tag mismatch → неверный пароль
      throw new PasswordError("Неверный пароль.");
    }

    return engine;
  }
}

// ─────────────────────────────────────────────
// Типизированные ошибки для обработки в UI
// ─────────────────────────────────────────────

export class PasswordError extends Error {
  readonly kind = "PasswordError" as const;
  constructor(message: string) {
    super(message);
    this.name = "PasswordError";
  }
}

export class SettingsCorruptedError extends Error {
  readonly kind = "SettingsCorruptedError" as const;
  constructor(message: string) {
    super(message);
    this.name = "SettingsCorruptedError";
  }
}
