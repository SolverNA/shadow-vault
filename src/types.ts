/**
 * Общие типы и интерфейсы плагина ShadowVault.
 * Этот файл — единственный источник правды для структур данных.
 */

/** Настройки плагина, сохраняемые в data.json хранилища Obsidian */
export interface PluginSettings {
  /**
   * Соль для PBKDF2 в hex-кодировке.
   * null = хранилище ещё не инициализировано (первый запуск).
   */
  saltHex: string | null;

  /**
   * Зашифрованный маркер верификации пароля в hex-кодировке.
   * При вводе пароля плагин расшифровывает этот блоб.
   * Если результат равен VERIFICATION_PLAINTEXT — пароль верный.
   * null = хранилище ещё не инициализировано.
   */
  verificationBlob: string | null;

  /**
   * Абсолютный путь к Теневому хранилищу (расшифрованные файлы).
   * Пустая строка = использовать путь по умолчанию (os.tmpdir/shadowvault-<id>).
   */
  shadowVaultPath: string;
}

export const DEFAULT_SETTINGS: PluginSettings = {
  saltHex: null,
  verificationBlob: null,
  shadowVaultPath: "",
};

/**
 * Константа для верификации пароля.
 * Шифруется при создании хранилища и расшифровывается при каждом входе.
 * Значение намеренно нейтральное — не раскрывает информацию о пользователе.
 */
export const VERIFICATION_PLAINTEXT = "ShadowVault::OK::v1";
