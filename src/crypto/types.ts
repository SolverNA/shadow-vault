/**
 * Единый интерфейс криптодвижка ShadowVault (ФАЗА 1).
 *
 * Две реализации:
 *   - NodeCryptoEngine  (node:crypto, синхронные buffer-методы + потоки)
 *   - WebCryptoEngine   (crypto.subtle, асинхронные buffer-методы)
 *
 * Обе дают идентичный формат v2 и идентичную деривацию ключа.
 *
 * Деривация теперь требует email+password (соль из email). На этой фазе
 * UI ещё не вводит email — вызывающий код временно прокидывает заглушку
 * (см. TODO в auth-service / main.ts).
 */

export interface CryptoEngine {
  /**
   * Деривирует мастер-ключ из email+password и загружает его в движок.
   * @param email    email пользователя (нормализуется внутри)
   * @param password пароль
   */
  deriveKey(email: string, password: string): Promise<void>;

  /** true, если ключ загружен. */
  isUnlocked(): boolean;

  /** Уничтожает ключ из памяти. */
  destroy(): void;
}

/**
 * Платформенный движок умеет шифровать "сырые" байты в формат v2.
 * Node-вариант синхронный, Web-вариант асинхронный — поэтому возвращаемые
 * типы оборачиваются в Promise через утилиты вызывающего кода.
 */
