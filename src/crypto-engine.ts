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
  CHUNK_BLOCK_SIZE,
  CHUNKED_THRESHOLD,
} from "./crypto/constants";
import { deriveMasterKey } from "./crypto/key-derivation";
import { nodeRequire } from "./crypto/platform";
import {
  detectFormat,
  parseChunkedContainer,
  writeChunkedHeader,
  writeSegment,
  CHUNKED_HEADER_LENGTH,
} from "./crypto/format";

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

    // Legacy 0-байтный .enc — артефакт старых версий. По единому контракту
    // пустых файлов трактуем его как пустой plaintext, а не как ошибку формата.
    if (container.length === 0) {
      return Buffer.alloc(0);
    }

    const fmt = detectFormat(container);
    if (fmt === "v2-chunked") {
      return this.decryptChunkedBuffer(container);
    }
    if (fmt !== "v2") {
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
   * Потоковое шифрование srcPath → dstPath.
   *
   * Маленькие/средние файлы (< CHUNKED_THRESHOLD) → цельный v2 (0x02):
   *   layout [header(5)][IV(12)][ciphertext][tag(16)]. Цельный формат сохраняет
   *   поведение для типичных заметок и байт-совместим с прошлыми версиями.
   *
   * Большие файлы (>= CHUNKED_THRESHOLD) → чанковый v2-chunked (0x03) РЕАЛЬНО
   *   потоково: читаем по blockSize, каждый блок шифруем отдельным AES-GCM
   *   (свой IV/tag) и сразу пишем сегмент в выходной поток — весь файл НЕ
   *   буферизуется в RAM. Mobile WebCrypto умеет это прочитать.
   *
   * Запись через .tmp + rename — атомарность.
   */
  async encryptStream(srcPath: string, dstPath: string): Promise<void> {
    this.assertUnlocked();
    const fs = this.fs;

    const size = (await fs.promises.stat(srcPath)).size;
    if (size >= CHUNKED_THRESHOLD) {
      await this.encryptStreamChunked(srcPath, dstPath);
      return;
    }

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
   * Реально потоковое чанковое шифрование (под-формат 0x03).
   * Читает src блоками по CHUNK_BLOCK_SIZE, каждый блок шифрует независимым
   * AES-GCM и дописывает сегмент в выход. Пиковая память ~ один блок.
   */
  private async encryptStreamChunked(srcPath: string, dstPath: string): Promise<void> {
    const fs = this.fs;
    const crypto = this.crypto;
    const blockSize = CHUNK_BLOCK_SIZE;
    const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tmpPath = `${dstPath}.${unique}.tmp`;

    let writeStream: import("fs").WriteStream | null = null;
    try {
      writeStream = fs.createWriteStream(tmpPath);
      const ws = writeStream;
      const writeChunk = (data: Uint8Array): Promise<void> =>
        new Promise((resolve, reject) => {
          ws.write(Buffer.from(data), (err) => (err ? reject(err) : resolve()));
        });

      // Заголовок чанкового контейнера
      await writeChunk(writeChunkedHeader(blockSize));

      // Поблочное чтение src через readStream с highWaterMark = blockSize
      const readStream = fs.createReadStream(srcPath, { highWaterMark: blockSize });
      let carry: Buffer = Buffer.alloc(0);

      const encryptAndWriteBlock = async (block: Buffer): Promise<void> => {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM_NODE, this.keyBuffer!, iv, {
          authTagLength: GCM_TAG_LENGTH,
        });
        const ct = Buffer.concat([cipher.update(block), cipher.final()]);
        const tag = cipher.getAuthTag();
        const body = Buffer.concat([ct, tag]);
        await writeChunk(writeSegment(iv, body));
      };

      await new Promise<void>((resolve, reject) => {
        readStream.on("error", reject);
        // Сериализуем обработку чанков: пока шифруем блок, поток на паузе.
        readStream.on("data", (chunk: Buffer) => {
          readStream.pause();
          carry = carry.length === 0 ? chunk : Buffer.concat([carry, chunk]);
          (async () => {
            // Отдаём блоки ровно по blockSize; хвост остаётся в carry.
            while (carry.length >= blockSize) {
              const block = carry.subarray(0, blockSize);
              carry = carry.subarray(blockSize);
              await encryptAndWriteBlock(Buffer.from(block));
            }
            readStream.resume();
          })().catch(reject);
        });
        readStream.on("end", () => {
          (async () => {
            if (carry.length > 0) {
              await encryptAndWriteBlock(carry);
              carry = Buffer.alloc(0);
            }
            resolve();
          })().catch(reject);
        });
      });

      await new Promise<void>((resolve, reject) => {
        ws.end((err?: Error | null) => (err ? reject(err) : resolve()));
      });
      writeStream = null;

      await fs.promises.rename(tmpPath, dstPath);
    } catch (err) {
      if (writeStream) writeStream.destroy();
      await fs.promises.unlink(tmpPath).catch(() => undefined);
      throw err;
    }
  }

  /** Расшифровывает чанковый контейнер (0x03) целиком в памяти. */
  private decryptChunkedBuffer(container: Buffer): Buffer {
    const crypto = this.crypto;
    const { segments } = parseChunkedContainer(container);
    const out: Buffer[] = [];
    for (const seg of segments) {
      const tagStart = seg.body.length - GCM_TAG_LENGTH;
      const ct = seg.body.subarray(0, tagStart);
      const tag = seg.body.subarray(tagStart);
      const decipher = crypto.createDecipheriv(ALGORITHM_NODE, this.keyBuffer!, seg.iv, {
        authTagLength: GCM_TAG_LENGTH,
      });
      decipher.setAuthTag(Buffer.from(tag));
      try {
        out.push(Buffer.concat([decipher.update(ct), decipher.final()]));
      } catch {
        throw new Error(
          "[NodeCryptoEngine] Расшифровка чанкового сегмента не удалась (Auth Tag mismatch)"
        );
      }
    }
    return Buffer.concat(out);
  }

  /**
   * Потоковая расшифровка srcPath → dstPath. Поддерживает оба под-формата:
   *   - v2 (0x02): tag в конце, наивный стриминг невозможен → читаем целиком.
   *   - v2-chunked (0x03): сегменты с длинами читаются по одному, каждый
   *     расшифровывается и пишется в выход — пиковая память ~ один блок.
   */
  async decryptStream(srcPath: string, dstPath: string): Promise<void> {
    this.assertUnlocked();
    const fs = this.fs;

    const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tmpPath = `${dstPath}.${unique}.tmp`;

    // Определяем под-формат по первым байтам без чтения всего файла.
    let isChunked = false;
    try {
      const fd = await fs.promises.open(srcPath, "r");
      try {
        const head = Buffer.alloc(HEADER_LENGTH);
        await fd.read(head, 0, HEADER_LENGTH, 0);
        isChunked = detectFormat(head) === "v2-chunked";
      } finally {
        await fd.close();
      }
    } catch {
      // открыть/прочитать заголовок не вышло — обработаем ниже единым путём
    }

    try {
      if (isChunked) {
        await this.decryptStreamChunked(srcPath, tmpPath);
      } else {
        const container = await fs.promises.readFile(srcPath);
        const plain = this.decryptBuffer(container);
        await fs.promises.writeFile(tmpPath, plain);
      }
      await fs.promises.rename(tmpPath, dstPath);
    } catch (err) {
      await new Promise<void>((res) => fs.unlink(tmpPath, () => res()));
      if (err instanceof Error && /Auth Tag mismatch|формат|сегмент/.test(err.message)) {
        throw new Error(`[NodeCryptoEngine] Потоковая расшифровка: ${err.message}`);
      }
      throw err;
    }
  }

  /**
   * Потоковая расшифровка чанкового контейнера: читаем заголовок, затем
   * посегментно по длинам, расшифровываем и пишем plaintext. Память ~ один блок.
   */
  private async decryptStreamChunked(srcPath: string, dstPath: string): Promise<void> {
    const fs = this.fs;
    const crypto = this.crypto;
    const fd = await fs.promises.open(srcPath, "r");
    let ws: import("fs").WriteStream | null = null;
    try {
      const header = Buffer.alloc(CHUNKED_HEADER_LENGTH);
      const hr = await fd.read(header, 0, CHUNKED_HEADER_LENGTH, 0);
      if (hr.bytesRead < CHUNKED_HEADER_LENGTH || detectFormat(header) !== "v2-chunked") {
        throw new Error("формат: чанковый заголовок повреждён");
      }

      ws = fs.createWriteStream(dstPath);
      const wstream = ws;
      const writeOut = (data: Buffer): Promise<void> =>
        new Promise((resolve, reject) => {
          wstream.write(data, (err) => (err ? reject(err) : resolve()));
        });

      let pos = CHUNKED_HEADER_LENGTH;
      const lenBuf = Buffer.alloc(4);
      // Размер файла, чтобы понять где конец.
      const total = (await fd.stat()).size;

      while (pos < total) {
        const lr = await fd.read(lenBuf, 0, 4, pos);
        if (lr.bytesRead < 4) throw new Error("формат: обрезан префикс сегмента");
        const segLen =
          (lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24)) >>> 0;
        pos += 4;
        if (segLen < IV_LENGTH + GCM_TAG_LENGTH || pos + segLen > total) {
          throw new Error("формат: неверная длина сегмента");
        }
        const seg = Buffer.alloc(segLen);
        await fd.read(seg, 0, segLen, pos);
        pos += segLen;

        const iv = seg.subarray(0, IV_LENGTH);
        const tagStart = segLen - GCM_TAG_LENGTH;
        const ct = seg.subarray(IV_LENGTH, tagStart);
        const tag = seg.subarray(tagStart);
        const decipher = crypto.createDecipheriv(ALGORITHM_NODE, this.keyBuffer!, iv, {
          authTagLength: GCM_TAG_LENGTH,
        });
        decipher.setAuthTag(tag);
        let plain: Buffer;
        try {
          plain = Buffer.concat([decipher.update(ct), decipher.final()]);
        } catch {
          throw new Error("сегмент: Auth Tag mismatch");
        }
        await writeOut(plain);
      }

      await new Promise<void>((resolve, reject) => {
        wstream.end((err?: Error | null) => (err ? reject(err) : resolve()));
      });
      ws = null;
    } finally {
      if (ws) ws.destroy();
      await fd.close().catch(() => undefined);
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
