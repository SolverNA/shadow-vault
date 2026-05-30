/**
 * WebCryptoEngine — WebCrypto-реализация единого криптоядра ShadowVault (ФАЗА 1).
 *
 * Работает на мобильных платформах (и в браузере), а также в Node 16+ через
 * crypto.subtle. Даёт БАЙТ-В-БАЙТ тот же формат v2, что и NodeCryptoEngine.
 *
 * Формат файла v2:
 *   [MAGIC "SVLT" (4)] [version 0x02 (1)] [IV (12)] [ciphertext‖GCM-tag(16 в конце)]
 *
 * WebCrypto AES-GCM сам возвращает ciphertext‖tag, поэтому body кладётся как есть.
 */

import { IV_LENGTH, GCM_TAG_LENGTH, KEY_LENGTH } from "./crypto/constants";
import { deriveMasterKey } from "./crypto/key-derivation";
import { getSubtle, randomBytes } from "./crypto/platform";
import { writeContainer, parseContainer } from "./crypto/format";

export class WebCryptoEngine {
  private key: CryptoKey | null = null;

  /**
   * Деривирует ключ из email+password (через общий key-derivation) и
   * импортирует его как AES-GCM CryptoKey.
   */
  async deriveKey(email: string, password: string): Promise<void> {
    const raw = await deriveMasterKey(email, password);
    const subtle = getSubtle();
    this.key = await subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM", length: KEY_LENGTH * 8 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /** Шифрует ArrayBuffer/Uint8Array в контейнер v2. */
  async encryptBuffer(plaintext: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    if (!this.key) throw new Error("[WebCryptoEngine] Ключ не загружен");

    const iv = randomBytes(IV_LENGTH);
    const subtle = getSubtle();
    const ctWithTag = await subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH * 8 },
      this.key,
      plaintext
    );

    const container = writeContainer(iv, new Uint8Array(ctWithTag));
    // Возвращаем ArrayBuffer (как ожидают существующие потребители)
    return container.buffer.slice(
      container.byteOffset,
      container.byteOffset + container.byteLength
    );
  }

  /** Расшифровывает контейнер v2 → ArrayBuffer. */
  async decryptBuffer(container: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    if (!this.key) throw new Error("[WebCryptoEngine] Ключ не загружен");

    const buf =
      container instanceof Uint8Array ? container : new Uint8Array(container);
    const { iv, body } = parseContainer(buf);

    const subtle = getSubtle();
    return await subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH * 8 },
      this.key,
      body
    );
  }

  /** Шифрует UTF-8 текст в контейнер v2. */
  async encryptText(plaintext: string): Promise<ArrayBuffer> {
    return this.encryptBuffer(new TextEncoder().encode(plaintext));
  }

  /** Расшифровывает контейнер v2 в UTF-8 текст. */
  async decryptText(container: ArrayBuffer | Uint8Array): Promise<string> {
    const decrypted = await this.decryptBuffer(container);
    return new TextDecoder().decode(decrypted);
  }

  /** Очищает ключ из памяти. */
  destroy(): void {
    this.key = null;
  }

  /** true, если ключ загружен. */
  isReady(): boolean {
    return this.key !== null;
  }

  /** Совместимость с интерфейсом CryptoEngine. */
  isUnlocked(): boolean {
    return this.key !== null;
  }

  /** Использует ли движок данный GCM tag length (служебная константа). */
  static readonly GCM_TAG_LENGTH = GCM_TAG_LENGTH;
}
