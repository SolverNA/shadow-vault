/**
 * Web Crypto API engine для кросс-платформенного шифрования
 * Заменяет Node.js crypto модуль для работы на мобильных платформах
 */

export class WebCryptoEngine {
  private key: CryptoKey | null = null;

  /**
   * Деривирует ключ из пароля используя PBKDF2
   * @param password - пароль пользователя
   */
  async deriveKey(password: string): Promise<void> {
    const encoder = new TextEncoder();
    const passwordBuf = encoder.encode(password);
    const domainBuf = encoder.encode("shadow-vault:v1");

    // Import password as key material
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      passwordBuf,
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    // Derive 256-bit key using PBKDF2
    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: domainBuf,
        iterations: 600_000,
        hash: "SHA-512",
      },
      keyMaterial,
      256
    );

    // Import as AES-GCM key
    this.key = await window.crypto.subtle.importKey(
      "raw",
      derivedBits,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Шифрует данные используя AES-GCM
   * @param plaintext - данные для шифрования
   * @returns зашифрованные данные (IV + ciphertext + auth tag)
   */
  async encryptBuffer(plaintext: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.key) throw new Error("Key not derived");

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      this.key,
      plaintext
    );

    // Format: IV (12 bytes) + ciphertext (includes auth tag)
    const result = new Uint8Array(12 + ciphertext.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertext), 12);
    return result.buffer;
  }

  /**
   * Расшифровывает данные используя AES-GCM
   * @param encrypted - зашифрованные данные (IV + ciphertext + auth tag)
   * @returns расшифрованные данные
   */
  async decryptBuffer(encrypted: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.key) throw new Error("Key not derived");

    const view = new Uint8Array(encrypted);
    const iv = view.slice(0, 12);
    const ciphertext = view.slice(12);

    return await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      this.key,
      ciphertext
    );
  }

  /**
   * Шифрует текст (UTF-8)
   * @param plaintext - текст для шифрования
   * @returns зашифрованные данные
   */
  async encryptText(plaintext: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const buf = encoder.encode(plaintext);
    return await this.encryptBuffer(buf.buffer);
  }

  /**
   * Расшифровывает текст (UTF-8)
   * @param encrypted - зашифрованные данные
   * @returns расшифрованный текст
   */
  async decryptText(encrypted: ArrayBuffer): Promise<string> {
    const decrypted = await this.decryptBuffer(encrypted);
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  /**
   * Очищает ключ из памяти
   */
  destroy(): void {
    this.key = null;
  }

  /**
   * Проверяет, деривирован ли ключ
   */
  isReady(): boolean {
    return this.key !== null;
  }
}
