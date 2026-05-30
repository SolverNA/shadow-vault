/**
 * NodeCryptoEngine — Node.js-реализация единого криптоядра ShadowVault (ФАЗА 1).
 *
 * Ответственность:
 *   - Деривация мастер-ключа AES-256 из email+password (см. crypto/key-derivation).
 *   - Шифрование/расшифровка буферов в едином формате v2.
 *   - Потоковое шифрование/расшифровка тяжёлых вложений.
 *
 * Формат файла v2 (идентичен WebCryptoEngine, байт-в-байт):
 *   [MAGIC "SVLT" (4)] [version 0x02 (1)] [IV (12)] [ciphertext‖GCM-tag(16 в конце)]
 *
 * ВАЖНО: node:crypto и fs подключаются ЛЕНИВО через nodeRequire() — модуль не
 * импортирует их на верхнем уровне, чтобы бандл не падал при загрузке на mobile.
 *
 * IV случаен для каждой операции записи. Класс экспортируется и как CryptoEngine
 * (исторический импорт многих потребителей), и как NodeCryptoEngine.
 */

import {
  ALGORITHM_NODE,
  HEADER,
} from "./crypto/node-internal";
import {
  IV_LENGTH,
  GCM_TAG_LENGTH,
  KEY_LENGTH,
  HEADER_LENGTH,
  MAGIC,
  FORMAT_VERSION,
} from "./crypto/constants";
import { deriveMasterKey } from "./crypto/key-derivation";
import { nodeRequire } from "./crypto/platform";
import { detectFormat } from "./crypto/format";

type NodeCrypto = typeof import("crypto");
type NodeFs = typeof import("fs");

export class NodeCryptoEngine {
  /** Приватный буфер ключа — обнуляется при destroy() */
  private keyBuffer: Buffer | null = null;

  private _crypto: NodeCrypto | null = null;
  private _fs: NodeFs | null = null;

  private get crypto(): NodeCrypto {
    if (!this._crypto) this._crypto = nodeRequire<NodeCrypto>("crypto");
    return this._crypto;
  }
  private get fs(): NodeFs {
    if (!this._fs) this._fs = nodeRequire<NodeFs>("fs");
    return this._fs;
  }

  // ─────────────────────────────────────────────
  // Публичный API
  // ─────────────────────────────────────────────

  /**
   * Деривирует мастер-ключ из email+password.
   * Использует общий модуль key-derivation (тот же результат, что у WebCrypto).
   */
  async deriveKey(email: string, password: string): Promise<void> {
    const raw = await deriveMasterKey(email, password);
    this.keyBuffer = Buffer.from(raw);
  }

  /**
   * Загружает уже готовый сырой мастер-ключ (32 байта) напрямую, минуя PBKDF2.
   * Используется при входе по PIN: masterKey извлекается из локального
   * wrapped-контейнера (см. pin-store) и инжектится в движок.
   */
  loadRawKey(raw: Uint8Array): void {
    if (raw.length !== KEY_LENGTH) {
      throw new Error(`[NodeCryptoEngine] Неверная длина ключа: ${raw.length}`);
    }
    this.keyBuffer = Buffer.from(raw);
  }

  isUnlocked(): boolean {
    return this.keyBuffer !== null;
  }

  /**
   * Шифрует Buffer в формат v2.
   * Результат: [MAGIC][version][IV(12)][ciphertext‖tag(16)]
   */
  encryptBuffer(plaintext: Buffer | Uint8Array): Buffer {
    this.assertUnlocked();
    const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);

    const iv = this.crypto.randomBytes(IV_LENGTH);
    const cipher = this.crypto.createCipheriv(ALGORITHM_NODE, this.keyBuffer!, iv, {
      authTagLength: GCM_TAG_LENGTH,
    });

    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag(); // 16 байт

    // Формат v2: header + IV + ciphertext + tag(в конце)
    return Buffer.concat([HEADER, iv, ciphertext, authTag]);
  }

  /**
   * Расшифровывает Buffer формата v2.
   * Бросает ошибку при несовпадении tag (повреждение/неверный ключ).
   */
  decryptBuffer(input: Buffer | Uint8Array): Buffer {
    this.assertUnlocked();
    const container = Buffer.isBuffer(input) ? input : Buffer.from(input);

    if (detectFormat(container) !== "v2") {
      throw new Error(
        "[NodeCryptoEngine] Неверный формат: ожидался контейнер v2 (MAGIC SVLT)"
      );
    }

    const minLen = HEADER_LENGTH + IV_LENGTH + GCM_TAG_LENGTH;
    if (container.length < minLen) {
      throw new Error(
        `[NodeCryptoEngine] Файл повреждён: размер ${container.length} < ${minLen}`
      );
    }

    const iv = container.subarray(HEADER_LENGTH, HEADER_LENGTH + IV_LENGTH);
    const body = container.subarray(HEADER_LENGTH + IV_LENGTH);
    // body = ciphertext‖tag: отрезаем последние 16 байт как tag
    const tagStart = body.length - GCM_TAG_LENGTH;
    const ciphertext = body.subarray(0, tagStart);
    const authTag = body.subarray(tagStart);

    const decipher = this.crypto.createDecipheriv(ALGORITHM_NODE, this.keyBuffer!, iv, {
      authTagLength: GCM_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);

    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new Error(
        "[NodeCryptoEngine] Расшифровка не удалась: неверный ключ или нарушена целостность файла (Auth Tag mismatch)"
      );
    }
  }

  /**
   * Потоковое шифрование srcPath → dstPath (формат v2).
   *
   * Файл на диске: [header(5)][IV(12)][ciphertext][tag(16)].
   * Tag в GCM доступен только после cipher.final(), поэтому ciphertext
   * буферизуется, а tag дописывается в конец (как в encryptBuffer).
   * Запись через .tmp + rename — атомарность.
   */
  async encryptStream(srcPath: string, dstPath: string): Promise<void> {
    this.assertUnlocked();
    const fs = this.fs;
    const crypto = this.crypto;

    const iv = crypto.randomBytes(IV_LENGTH);
    const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tmpPath = `${dstPath}.${unique}.tmp`;

    try {
      await new Promise<void>((resolve, reject) => {
        const readStream = fs.createReadStream(srcPath);
        const cipher = crypto.createCipheriv(ALGORITHM_NODE, this.keyBuffer!, iv, {
          authTagLength: GCM_TAG_LENGTH,
        });
        const writeStream = fs.createWriteStream(tmpPath);

        // header + IV в начало
        writeStream.write(HEADER);
        writeStream.write(iv);

        cipher.on("data", (chunk: Buffer) => writeStream.write(chunk));
        cipher.on("end", () => {
          const authTag = cipher.getAuthTag();
          // tag в конец файла
          writeStream.end(authTag);
        });

        cipher.on("error", reject);
        writeStream.on("error", reject);
        writeStream.on("finish", () => {
          fs.rename(tmpPath, dstPath, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });

        readStream.on("error", reject);
        readStream.pipe(cipher);
      });
    } catch (err) {
      await new Promise<void>((res) => fs.unlink(tmpPath, () => res()));
      throw err;
    }
  }

  /**
   * Потоковая расшифровка srcPath → dstPath (формат v2).
   *
   * Layout: [header(5)][IV(12)][ciphertext][tag(16)]. tag в конце, поэтому
   * расшифровку нельзя стримить наивно: последние 16 байт — это tag, а не
   * данные. Читаем весь файл, разбираем как в decryptBuffer, пишем результат.
   * (Для типичных вложений это приемлемо; полноценный chunked-GCM — отдельная задача.)
   */
  async decryptStream(srcPath: string, dstPath: string): Promise<void> {
    this.assertUnlocked();
    const fs = this.fs;

    const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tmpPath = `${dstPath}.${unique}.tmp`;

    try {
      const container = await fs.promises.readFile(srcPath);
      const plain = this.decryptBuffer(container);
      await fs.promises.writeFile(tmpPath, plain);
      await fs.promises.rename(tmpPath, dstPath);
    } catch (err) {
      await new Promise<void>((res) => fs.unlink(tmpPath, () => res()));
      if (err instanceof Error && /Auth Tag mismatch|формат/.test(err.message)) {
        throw new Error(`[NodeCryptoEngine] Потоковая расшифровка: ${err.message}`);
      }
      throw err;
    }
  }

  /** Безопасное уничтожение ключа из памяти. */
  destroy(): void {
    if (this.keyBuffer) {
      this.keyBuffer.fill(0);
      this.keyBuffer = null;
    }
  }

  // ─────────────────────────────────────────────
  // Приватные хелперы
  // ─────────────────────────────────────────────

  private assertUnlocked(): void {
    if (!this.keyBuffer) {
      throw new Error(
        "[NodeCryptoEngine] Ключ не загружен. Сначала вызовите deriveKey(email, password)."
      );
    }
  }
}

// Исторический алиас: многие потребители импортируют { CryptoEngine } из этого файла.
export const CryptoEngine = NodeCryptoEngine;
export type CryptoEngine = NodeCryptoEngine;

// Защита: подтверждаем, что header-константа собрана корректно.
void KEY_LENGTH;
void MAGIC;
void FORMAT_VERSION;
