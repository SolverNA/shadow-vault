/**
 * AuthService — чистая бизнес-логика аутентификации без зависимости от Obsidian API.
 * Тестируется в изоляции (Node.js), не требует моков UI.
 *
 * Ответственность:
 *   - Определить, первый ли это запуск (нет соли в настройках).
 *   - При первом запуске: сгенерировать соль, сохранить верификационный блоб.
 *   - При повторном запуске: проверить пароль через верификационный блоб.
 *   - Вернуть готовый CryptoEngine с загруженным ключом.
 */

import * as fsp from "fs/promises";
import { CryptoEngine } from "./crypto-engine";
import {
  PluginSettings,
  VERIFICATION_PLAINTEXT,
} from "./types";

export type SaveSettingsFn = (settings: PluginSettings) => Promise<void>;

export interface AuthResult {
  engine: CryptoEngine;
  /** true если это был первый запуск и настройки уже сохранены */
  isFirstRun: boolean;
}

export interface AuthOptions {
  /**
   * Ручная соль в hex-формате — для восстановления хранилища когда data.json
   * утерян (orphan-encrypted vault). При наличии валидируется через попытку
   * расшифровать любой .enc файл из vault'а — auth tag GCM = доказательство
   * что комбинация пароль+соль правильная.
   */
  manualSaltHex?: string;
  /**
   * Путь к одному зашифрованному файлу (абсолютный) для верификации
   * комбинации password+manualSaltHex. Обязателен если передан manualSaltHex
   * И settings.saltHex===null (нет verificationBlob для проверки).
   */
  verifyEncFileAbs?: string;
}

export class AuthService {
  /**
   * Основной метод аутентификации.
   *
   * Логика:
   *   1. Если saltHex в настройках null → первый запуск.
   *      Генерируем соль, деривируем ключ, создаём верификационный блоб,
   *      сохраняем настройки.
   *   2. Если saltHex есть → повторный запуск.
   *      Деривируем ключ с известной солью, пробуем расшифровать verificationBlob.
   *      Если не вышло → бросаем PasswordError (неверный пароль).
   *
   * @param password   Пароль, введённый пользователем
   * @param settings   Текущие настройки плагина (из data.json)
   * @param saveFn     Функция сохранения настроек (внедряется извне для тестируемости)
   * @returns          AuthResult с готовым engine и флагом isFirstRun
   */
  async authenticate(
    password: string,
    settings: PluginSettings,
    saveFn: SaveSettingsFn,
    opts: AuthOptions = {}
  ): Promise<AuthResult> {
    if (!password.trim()) {
      throw new PasswordError("Пароль не может быть пустым.");
    }

    // ── Восстановление по соли (orphan vault) ─────────────────────────────
    // Сценарий: settings.saltHex отсутствует ИЛИ пользователь явно ввёл соль.
    // Используем переданную соль и верифицируем через попытку расшифровать
    // любой .enc файл — если AES-GCM auth tag сошёлся, комбинация верна.
    if (opts.manualSaltHex) {
      return AuthService.authenticateWithManualSalt(
        password, opts.manualSaltHex, settings, saveFn, opts.verifyEncFileAbs
      );
    }

    const engine = new CryptoEngine();
    const isFirstRun = settings.saltHex === null;

    if (isFirstRun) {
      // ── Первый запуск: создаём хранилище ──────────────────────────────────
      const saltHex = await engine.deriveKey(password);

      // Шифруем маркер верификации — чтобы при следующем входе можно было
      // проверить пароль, не расшифровывая реальные файлы
      const verificationBuf = engine.encryptBuffer(
        Buffer.from(VERIFICATION_PLAINTEXT, "utf8")
      );

      const updatedSettings: PluginSettings = {
        ...settings,
        saltHex,
        verificationBlob: verificationBuf.toString("hex"),
      };

      await saveFn(updatedSettings);
      return { engine, isFirstRun: true };
    }

    // ── Повторный запуск: проверяем пароль ────────────────────────────────
    const verifiedEngine = await AuthService.verifyPassword(password, settings);
    // Освобождаем "пустой" engine — используем тот, что вернула verifyPassword
    engine.destroy();
    return { engine: verifiedEngine, isFirstRun: false };
  }

  /**
   * Аутентификация с ручной солью — для восстановления orphan-encrypted vault
   * (data.json утерян, но у пользователя есть бэкап соли) или для проверки
   * сохранённой соли в обычном flow.
   *
   * Стратегия верификации:
   *   1. Если есть verificationBlob — сверяем по нему (быстрее, надёжнее).
   *   2. Иначе пробуем расшифровать verifyEncFileAbs — auth tag GCM
   *      выступает доказательством что password+salt правильные.
   *   3. После успеха сохраняем соль и новый verificationBlob в settings.
   */
  static async authenticateWithManualSalt(
    password: string,
    manualSaltHex: string,
    settings: PluginSettings,
    saveFn: SaveSettingsFn,
    verifyEncFileAbs?: string
  ): Promise<AuthResult> {
    // Поверхностная валидация формата соли — hex, чётная длина
    const trimmedHex = manualSaltHex.trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(trimmedHex) || trimmedHex.length % 2 !== 0) {
      throw new PasswordError(
        "Соль должна быть hex-строкой (только цифры и a–f, чётная длина)."
      );
    }

    const engine = new CryptoEngine();
    await engine.deriveKey(password, trimmedHex);

    // Способ 1: verificationBlob (быстрая проверка)
    if (settings.verificationBlob) {
      try {
        const decrypted = engine.decryptBuffer(
          Buffer.from(settings.verificationBlob, "hex")
        );
        if (decrypted.toString("utf8") !== VERIFICATION_PLAINTEXT) {
          engine.destroy();
          throw new PasswordError("Верификация не прошла: неверный пароль или соль.");
        }
      } catch (err) {
        engine.destroy();
        if (err instanceof PasswordError) throw err;
        throw new PasswordError("Неверный пароль или соль.");
      }
    } else if (verifyEncFileAbs) {
      // Способ 2: попытка расшифровать любой .enc — auth tag доказывает корректность
      try {
        const encBuf = await fsp.readFile(verifyEncFileAbs);
        if (encBuf.length > 0) engine.decryptBuffer(encBuf);
        // Если файл пустой — допускаем, валидация невозможна, но это не ошибка
      } catch (err) {
        engine.destroy();
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "ENOENT") {
          throw new PasswordError(
            "Файл для верификации не найден. Введите соль ещё раз или восстановите data.json."
          );
        }
        throw new PasswordError(
          "Неверный пароль или соль (не удалось расшифровать .enc файл)."
        );
      }
    } else {
      // Нечем верифицировать — отказываем
      engine.destroy();
      throw new SettingsCorruptedError(
        "Невозможно проверить корректность соли: нет ни verificationBlob, ни .enc файла."
      );
    }

    // Сохраняем соль и (если её не было) генерируем новый verificationBlob
    const newVerificationBuf = engine.encryptBuffer(
      Buffer.from(VERIFICATION_PLAINTEXT, "utf8")
    );
    await saveFn({
      ...settings,
      saltHex: trimmedHex,
      verificationBlob: newVerificationBuf.toString("hex"),
    });

    return { engine, isFirstRun: false };
  }

  /**
   * Деривирует ключ и проверяет его корректность через verificationBlob.
   *
   * Используется и в обычной аутентификации, и в смене пароля
   * (чтобы независимо от активной сессии убедиться, что старый пароль верен).
   *
   * @returns CryptoEngine с загруженным ключом (вызывающий обязан destroy())
   * @throws  PasswordError если пароль неверный
   * @throws  SettingsCorruptedError если verificationBlob отсутствует
   */
  static async verifyPassword(
    password: string,
    settings: PluginSettings
  ): Promise<CryptoEngine> {
    if (settings.saltHex === null) {
      throw new SettingsCorruptedError("Соль отсутствует — хранилище не инициализировано.");
    }
    if (!settings.verificationBlob) {
      throw new SettingsCorruptedError(
        "Файл настроек повреждён: verificationBlob отсутствует. " +
        "Восстановите data.json из резервной копии."
      );
    }

    const engine = new CryptoEngine();
    await engine.deriveKey(password, settings.saltHex);

    try {
      const decrypted = engine.decryptBuffer(
        Buffer.from(settings.verificationBlob, "hex")
      );
      if (decrypted.toString("utf8") !== VERIFICATION_PLAINTEXT) {
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
