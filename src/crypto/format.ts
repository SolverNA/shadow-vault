/**
 * Контейнер зашифрованного файла v2 и детектор форматов.
 *
 * Формат v2 (0x02, цельный):
 *   [MAGIC "SVLT" (4)] [version 0x02 (1)] [IV (12)] [ciphertext‖GCM-tag(16 в конце)]
 *
 * Формат v2-chunked (0x03, для больших файлов):
 *   [MAGIC "SVLT" (4)] [version 0x03 (1)] [blockSize u32 LE (4)]
 *   затем сегменты: [segLen u32 LE (4)] [IV (12)] [ciphertext‖tag (16)]
 *   Каждый сегмент — независимый AES-GCM (свой IV/tag), шифрует blockSize байт.
 *
 * Layout одинаков для Node и WebCrypto:
 *   - WebCrypto AES-GCM сам возвращает ciphertext‖tag;
 *   - в Node ciphertext и getAuthTag() склеиваются в том же порядке.
 * Писать чанково умеет пока только desktop; читать чанково обязаны ОБА.
 */

import {
  MAGIC,
  MAGIC_LENGTH,
  FORMAT_VERSION,
  FORMAT_VERSION_CHUNKED,
  HEADER_LENGTH,
  IV_LENGTH,
  GCM_TAG_LENGTH,
} from "./constants";

export type EncryptedFormat =
  | "v2"
  | "v2-chunked"
  | "legacy-node"
  | "legacy-web"
  | "unknown";

/** Длина заголовка чанкового контейнера: MAGIC(4)+version(1)+blockSize u32(4) = 9 */
export const CHUNKED_HEADER_LENGTH = HEADER_LENGTH + 4;
/** Длина префикса длины сегмента (u32 LE) */
export const SEGMENT_LEN_PREFIX = 4;

/** Собирает контейнер v2 из IV и body (ciphertext‖tag). */
export function writeContainer(iv: Uint8Array, body: Uint8Array): Uint8Array {
  if (iv.length !== IV_LENGTH) {
    throw new Error(`[format] IV должен быть ${IV_LENGTH} байт, получено ${iv.length}`);
  }
  const out = new Uint8Array(HEADER_LENGTH + IV_LENGTH + body.length);
  out.set(MAGIC, 0);
  out[MAGIC_LENGTH] = FORMAT_VERSION;
  out.set(iv, HEADER_LENGTH);
  out.set(body, HEADER_LENGTH + IV_LENGTH);
  return out;
}

/**
 * Разбирает контейнер v2, возвращает IV и body (ciphertext‖tag).
 * Бросает ошибку, если префикс/размер не соответствуют формату v2.
 */
export function parseContainer(buf: Uint8Array): { iv: Uint8Array; body: Uint8Array } {
  if (detectFormat(buf) !== "v2") {
    throw new Error("[format] Не контейнер v2 (неверный MAGIC/version)");
  }
  const min = HEADER_LENGTH + IV_LENGTH + GCM_TAG_LENGTH;
  if (buf.length < min) {
    throw new Error(`[format] Контейнер повреждён: размер ${buf.length} < ${min}`);
  }
  const iv = buf.subarray(HEADER_LENGTH, HEADER_LENGTH + IV_LENGTH);
  const body = buf.subarray(HEADER_LENGTH + IV_LENGTH);
  return { iv, body };
}

/** Проверяет наличие MAGIC-префикса и возвращает version-байт, иначе null. */
function magicVersion(buf: Uint8Array): number | null {
  if (buf.length < HEADER_LENGTH) return null;
  for (let i = 0; i < MAGIC_LENGTH; i++) {
    if (buf[i] !== MAGIC[i]) return null;
  }
  return buf[MAGIC_LENGTH];
}

/** Проверяет наличие префикса MAGIC+version v2 (цельный). */
function hasV2Header(buf: Uint8Array): boolean {
  return magicVersion(buf) === FORMAT_VERSION;
}

/** Проверяет наличие префикса MAGIC+version v2-chunked (0x03). */
function hasChunkedHeader(buf: Uint8Array): boolean {
  return magicVersion(buf) === FORMAT_VERSION_CHUNKED;
}

/** Один расшифрованный сегмент чанкового контейнера: IV + body(ct‖tag). */
export interface ChunkSegment {
  iv: Uint8Array;
  body: Uint8Array;
}

/** Собирает заголовок чанкового контейнера: MAGIC + 0x03 + blockSize u32 LE. */
export function writeChunkedHeader(blockSize: number): Uint8Array {
  const out = new Uint8Array(CHUNKED_HEADER_LENGTH);
  out.set(MAGIC, 0);
  out[MAGIC_LENGTH] = FORMAT_VERSION_CHUNKED;
  // blockSize как u32 LE
  out[HEADER_LENGTH] = blockSize & 0xff;
  out[HEADER_LENGTH + 1] = (blockSize >>> 8) & 0xff;
  out[HEADER_LENGTH + 2] = (blockSize >>> 16) & 0xff;
  out[HEADER_LENGTH + 3] = (blockSize >>> 24) & 0xff;
  return out;
}

/** Кодирует один сегмент: [segLen u32 LE][IV][ct‖tag]. */
export function writeSegment(iv: Uint8Array, body: Uint8Array): Uint8Array {
  if (iv.length !== IV_LENGTH) {
    throw new Error(`[format] segment IV должен быть ${IV_LENGTH} байт`);
  }
  const segLen = IV_LENGTH + body.length;
  const out = new Uint8Array(SEGMENT_LEN_PREFIX + segLen);
  out[0] = segLen & 0xff;
  out[1] = (segLen >>> 8) & 0xff;
  out[2] = (segLen >>> 16) & 0xff;
  out[3] = (segLen >>> 24) & 0xff;
  out.set(iv, SEGMENT_LEN_PREFIX);
  out.set(body, SEGMENT_LEN_PREFIX + IV_LENGTH);
  return out;
}

/** Читает u32 LE из буфера по смещению. */
function readU32LE(buf: Uint8Array, off: number): number {
  return (
    buf[off] |
    (buf[off + 1] << 8) |
    (buf[off + 2] << 16) |
    (buf[off + 3] << 24)
  ) >>> 0;
}

/**
 * Разбирает целиком прочитанный чанковый контейнер на blockSize и список
 * сегментов (для расшифровки в памяти — используется WebCrypto на mobile и
 * Node-fallback при небольших файлах). Для реально потокового чтения на desktop
 * сегменты вычитываются по длинам без загрузки всего файла (см. NodeCryptoEngine).
 */
export function parseChunkedContainer(buf: Uint8Array): {
  blockSize: number;
  segments: ChunkSegment[];
} {
  if (!hasChunkedHeader(buf)) {
    throw new Error("[format] Не контейнер v2-chunked (неверный MAGIC/version)");
  }
  if (buf.length < CHUNKED_HEADER_LENGTH) {
    throw new Error("[format] Чанковый контейнер повреждён: нет заголовка");
  }
  const blockSize = readU32LE(buf, HEADER_LENGTH);
  const segments: ChunkSegment[] = [];
  let off = CHUNKED_HEADER_LENGTH;
  while (off < buf.length) {
    if (off + SEGMENT_LEN_PREFIX > buf.length) {
      throw new Error("[format] Чанковый контейнер повреждён: обрезан префикс сегмента");
    }
    const segLen = readU32LE(buf, off);
    off += SEGMENT_LEN_PREFIX;
    if (segLen < IV_LENGTH + GCM_TAG_LENGTH || off + segLen > buf.length) {
      throw new Error("[format] Чанковый контейнер повреждён: неверная длина сегмента");
    }
    const iv = buf.subarray(off, off + IV_LENGTH);
    const body = buf.subarray(off + IV_LENGTH, off + segLen);
    segments.push({ iv, body });
    off += segLen;
  }
  return { blockSize, segments };
}

/**
 * Детектор формата зашифрованного буфера.
 *
 * - "v2": присутствует префикс MAGIC "SVLT" + version 0x02.
 * - "legacy-node"/"legacy-web": без префикса, различить их по содержимому
 *   надёжно нельзя (оба начинаются с 12 байт IV и имеют 16-байтный tag,
 *   отличается лишь позиция tag). Для будущей миграции (ФАЗА 4) обе ветки
 *   помечаем как "legacy-node" по умолчанию, если размер допускает legacy-layout.
 * - "unknown": слишком короткий или нераспознанный.
 *
 * Точное разделение legacy-node vs legacy-web делается на этапе миграции
 * методом trial-decrypt обоими способами — на этой фазе детектор лишь
 * отделяет v2 от не-v2.
 */
export function detectFormat(buf: Uint8Array): EncryptedFormat {
  if (hasV2Header(buf)) return "v2";
  if (hasChunkedHeader(buf)) return "v2-chunked";

  // legacy-layout: минимум IV(12) + tag(16)
  if (buf.length >= IV_LENGTH + GCM_TAG_LENGTH) {
    return "legacy-node";
  }
  return "unknown";
}

/**
 * Оценивает размер plaintext по полному буферу .enc БЕЗ расшифровки.
 *   - v2 (0x02): plaintext = длина − (HEADER+IV+tag) = длина − 33.
 *   - v2-chunked (0x03): Σ(segLen − IV − tag) по префиксам длин сегментов.
 *   - 0 байт (legacy-артефакт пустого файла): 0.
 *   - legacy/unknown: точного overhead нет — возвращаем длину буфера как есть
 *     (без грубого искажения).
 * Используется в stat() на mobile и desktop для согласованного размера.
 */
export function plaintextSizeFromContainer(buf: Uint8Array): number {
  if (buf.length === 0) return 0;
  const fmt = detectFormat(buf);

  if (fmt === "v2") {
    const overhead = HEADER_LENGTH + IV_LENGTH + GCM_TAG_LENGTH; // 33
    return buf.length >= overhead ? buf.length - overhead : buf.length;
  }

  if (fmt === "v2-chunked") {
    const segOverhead = IV_LENGTH + GCM_TAG_LENGTH;
    let off = CHUNKED_HEADER_LENGTH;
    let plaintext = 0;
    while (off + SEGMENT_LEN_PREFIX <= buf.length) {
      const segLen =
        (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
      if (segLen < segOverhead) break; // битый заголовок — прекращаем
      plaintext += segLen - segOverhead;
      off += SEGMENT_LEN_PREFIX + segLen;
    }
    return plaintext;
  }

  // legacy/unknown — не искажаем грубо.
  return buf.length;
}

/** Возвращает true, если буфер — цельный контейнер v2 (0x02). */
export function isV2(buf: Uint8Array): boolean {
  return hasV2Header(buf);
}

/** Возвращает true, если буфер — чанковый контейнер v2-chunked (0x03). */
export function isChunked(buf: Uint8Array): boolean {
  return hasChunkedHeader(buf);
}
