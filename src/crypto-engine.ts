/**
 * CryptoEngine — ядро криптографии плагина ShadowVault.
 *
 * Ответственность:
 *   - Деривация ключа AES-256 из пароля пользователя через PBKDF2 (SHA-512).
 *   - Шифрование и расшифровка буферов (Buffer API) для небольших файлов.
 *   - Потоковое шифрование/расшифровка (Stream API) для тяжёлых вложений (PDF, видео).
 *
 * Формат зашифрованного файла:
 *   [IV (12 байт)] [Auth Tag (16 байт)] [Зашифрованные данные (N байт)]
 *
 * ВАЖНО: IV генерируется случайно для каждой операции записи.
 * Повторное использование IV с одним ключом в GCM-режиме катастрофически
 * нарушает конфиденциальность — это не допускается нигде в коде.
 *
 * Соли НЕТ: ключ деривируется только из пароля + фиксированной доменной
 * константы. Это означает: одинаковый пароль всегда даёт одинаковый ключ.
 * Доменная константа защищает от переиспользования ключа в других приложениях,
 * использующих PBKDF2 от того же пароля. Восстановление возможно только по паролю,
 * никаких бэкапов соли не нужно.
 */

import * as crypto from "crypto";
import * as fs from "fs";

/** Параметры алгоритма шифрования — менять только осознанно */
const ALGORITHM = "aes-256-gcm" as const;
const IV_LENGTH = 12;         // байт, рекомендуется NIST для GCM
const AUTH_TAG_LENGTH = 16;   // байт, максимальный размер тега аутентификации GCM
const KEY_LENGTH = 32;        // байт = 256 бит

/** Параметры PBKDF2 — итерации выбраны для баланса безопасность/скорость (≈300 мс на типичном CPU) */
const PBKDF2_ITERATIONS = 310_000;
const PBKDF2_DIGEST = "sha512";

/**
 * Фиксированная доменная константа для PBKDF2.
 * Не секрет, не уникальна на vault — служит только для отделения ключей
 * ShadowVault от любых других приложений, которые могли бы дерировать
 * ключ из того же пароля.
 *
 * НЕ МЕНЯТЬ без миграции — изменение константы сделает все существующие
 * .enc файлы нерасшифровываемыми.
 */
const PBKDF2_DOMAIN = Buffer.from("shadow-vault:v1", "utf8");

export class CryptoEngine {
  /** Приватный буфер ключа — обнуляется при вызове destroy() */
  private keyBuffer: Buffer | null = null;

  // ─────────────────────────────────────────────
  // Публичный API
  // ─────────────────────────────────────────────

  /**
   * Деривирует ключ AES-256 из пароля через PBKDF2.
   * Соль не используется: вход PBKDF2 — только пароль и фиксированная
   * доменная константа PBKDF2_DOMAIN.
   *
   * @param password Пароль пользователя в открытом виде
   */
  async deriveKey(password: string): Promise<void> {
    // PBKDF2 запускается асинхронно, чтобы не блокировать UI-поток Obsidian
    const keyBuffer = await new Promise<Buffer>((resolve, reject) => {
      crypto.pbkdf2(
        password,
        PBKDF2_DOMAIN,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        PBKDF2_DIGEST,
        (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey);
        }
      );
    });

    this.keyBuffer = keyBuffer;
  }

  /**
   * Проверяет, загружен ли ключ (пользователь прошёл аутентификацию).
   */
  isUnlocked(): boolean {
    return this.keyBuffer !== null;
  }

  /**
   * Шифрует данные из Buffer.
   * Используется для текстовых заметок (.md, .canvas) — небольших файлов.
   *
   * Результат: Buffer с форматом [IV][Auth Tag][Ciphertext]
   */
  encryptBuffer(plaintext: Buffer): Buffer {
    this.assertUnlocked();

    // Уникальный IV для каждой операции — ключевое требование безопасности GCM
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.keyBuffer!, iv);

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Склеиваем: [IV (12)] [AuthTag (16)] [Ciphertext]
    return Buffer.concat([iv, authTag, encrypted]);
  }

  /**
   * Расшифровывает данные из Buffer.
   * Бросает ошибку если auth tag не совпал — файл повреждён или подменён.
   */
  decryptBuffer(ciphertext: Buffer): Buffer {
    this.assertUnlocked();

    if (ciphertext.length < IV_LENGTH + AUTH_TAG_LENGTH) {
      throw new Error(
        `[CryptoEngine] Файл повреждён: размер ${ciphertext.length} байт меньше минимального заголовка`
      );
    }

    // Разбираем заголовок по известным смещениям
    const iv = ciphertext.subarray(0, IV_LENGTH);
    const authTag = ciphertext.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const data = ciphertext.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, this.keyBuffer!, iv);
    decipher.setAuthTag(authTag);

    try {
      return Buffer.concat([decipher.update(data), decipher.final()]);
    } catch {
      // Бросаем явную ошибку: либо неверный пароль, либо файл изменён сторонним ПО
      throw new Error(
        "[CryptoEngine] Расшифровка не удалась: неверный ключ или нарушена целостность файла (Auth Tag mismatch)"
      );
    }
  }

  /**
   * Потоковое шифрование: читает из srcPath, пишет зашифрованный файл в dstPath.
   * Используется для PDF, изображений, аудио/видео — файлов, которые нельзя грузить в RAM целиком.
   *
   * Транзитная запись через временный файл + fs.rename обеспечивает атомарность:
   * если процесс прервётся во время записи, оригинальный файл не будет повреждён.
   */
  async encryptStream(srcPath: string, dstPath: string): Promise<void> {
    this.assertUnlocked();

    const iv = crypto.randomBytes(IV_LENGTH);
    // Уникальный tmp-suffix защищает от race между параллельными encryptStream
    // на одном dst — иначе два потока пишут в один tmp, потом dst получает torn data.
    const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tmpPath = `${dstPath}.${unique}.tmp`;

    try {
      await new Promise<void>((resolve, reject) => {
        const readStream = fs.createReadStream(srcPath);
        const cipher = crypto.createCipheriv(ALGORITHM, this.keyBuffer!, iv);
        const writeStream = fs.createWriteStream(tmpPath);

        // Записываем IV в начало файла до начала шифрованного потока
        writeStream.write(iv);

        // Auth Tag в GCM-режиме доступен только ПОСЛЕ cipher.final(),
        // поэтому мы буферизируем зашифрованный контент и вставляем тег перед ним
        const chunks: Buffer[] = [];

        cipher.on("data", (chunk: Buffer) => chunks.push(chunk));
        cipher.on("end", () => {
          const authTag = cipher.getAuthTag();
          writeStream.write(authTag);
          for (const chunk of chunks) writeStream.write(chunk);
          writeStream.end();
        });

        cipher.on("error", reject);
        writeStream.on("error", reject);
        writeStream.on("finish", () => {
          // Атомарная замена: tmpPath → dstPath
          fs.rename(tmpPath, dstPath, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });

        readStream.on("error", reject);
        readStream.pipe(cipher);
      });
    } catch (err) {
      // Удаляем временный файл при любой ошибке
      await new Promise<void>((res) => fs.unlink(tmpPath, () => res()));
      throw err;
    }
  }

  /**
   * Потоковая расшифровка: читает зашифрованный файл из srcPath, пишет открытый текст в dstPath.
   * Auth Tag проверяется при cipher.final() — если тег не совпадает, деструктор бросит ошибку.
   */
  async decryptStream(srcPath: string, dstPath: string): Promise<void> {
    this.assertUnlocked();

    const unique = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tmpPath = `${dstPath}.${unique}.tmp`;

    try {
    await new Promise<void>((resolve, reject) => {
      const readStream = fs.createReadStream(srcPath);
      const writeStream = fs.createWriteStream(tmpPath);

      // Собираем первые IV_LENGTH + AUTH_TAG_LENGTH байт как заголовок,
      // остальное отправляем в decipher потоком
      let headerBuf = Buffer.alloc(0);
      let headerConsumed = false;
      let decipher: crypto.DecipherGCM | null = null;

      readStream.on("data", (chunk: Buffer) => {
        if (!headerConsumed) {
          headerBuf = Buffer.concat([headerBuf, chunk]);

          if (headerBuf.length >= IV_LENGTH + AUTH_TAG_LENGTH) {
            // Заголовок собран — инициализируем decipher
            const iv = headerBuf.subarray(0, IV_LENGTH);
            const authTag = headerBuf.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
            const rest = headerBuf.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

            decipher = crypto.createDecipheriv(ALGORITHM, this.keyBuffer!, iv);
            decipher.setAuthTag(authTag);
            decipher.pipe(writeStream);
            decipher.on("error", (err) => {
              writeStream.destroy();
              reject(new Error(`[CryptoEngine] Потоковая расшифровка: ${err.message}`));
            });

            headerConsumed = true;
            if (rest.length > 0) decipher.write(rest);
          }
        } else {
          decipher!.write(chunk);
        }
      });

      readStream.on("end", () => {
        if (!decipher) {
          reject(new Error("[CryptoEngine] Файл слишком мал — заголовок не найден"));
          return;
        }
        decipher.end();
      });

      readStream.on("error", reject);

      writeStream.on("finish", () => {
        fs.rename(tmpPath, dstPath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      writeStream.on("error", reject);
    });
    } catch (err) {
      await new Promise<void>((res) => fs.unlink(tmpPath, () => res()));
      throw err;
    }
  }

  /**
   * Безопасное уничтожение ключа из оперативной памяти.
   * Вызывать при корректном завершении сессии и при краше (если есть возможность).
   * Обнуление буфера снижает вероятность утечки ключа при анализе дампа памяти.
   */
  destroy(): void {
    if (this.keyBuffer) {
      this.keyBuffer.fill(0); // перезапись нулями перед GC
      this.keyBuffer = null;
    }
  }

  // ─────────────────────────────────────────────
  // Приватные хелперы
  // ─────────────────────────────────────────────

  /** Бросает исключение если ключ не загружен — защита от случайного вызова без деривации */
  private assertUnlocked(): void {
    if (!this.keyBuffer) {
      throw new Error(
        "[CryptoEngine] Ключ не загружен. Сначала вызовите deriveKey() с паролем пользователя."
      );
    }
  }
}
