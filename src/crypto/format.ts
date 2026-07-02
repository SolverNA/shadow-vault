/**
 * Контейнер зашифрованного файла v2 и детектор форматов.
 *
 * Формат v2 (0x02, цельный):
 *   [MAGIC "SVLT" (4)] [version 0x02 (1)] [IV (12)] [ciphertext‖GCM-tag(16 в конце)]
 *
 * Формат v2-chunked (0x03, УСТАРЕЛ для записи — только чтение):
 *   [MAGIC "SVLT" (4)] [version 0x03 (1)] [blockSize u32 LE (4)]
 *   затем сегменты: [segLen u32 LE (4)] [IV (12)] [ciphertext‖tag (16)]
 *   Каждый сегмент — независимый AES-GCM (свой IV/tag), шифрует blockSize байт.
 *   НЕДОСТАТОК: сегменты не связаны — перестановка/удаление/усечение/подстановка
 *   не детектируются. Новые файлы пишутся ТОЛЬКО в 0x04.
 *
 * Формат v2-chunked v2 (0x04, текущий для записи):
 *   [MAGIC "SVLT" (4)] [version 0x04 (1)] [blockSize u32 LE (4)]
 *   [segCount u32 LE (4)] [fileId (16, случайный)]
 *   затем сегменты — байт-в-байт как в 0x03.
 *   AAD сегмента i = весь 29-байтный заголовок ‖ u32 LE(i): GCM-tag каждого
 *   сегмента аутентифицирует его индекс, общее число сегментов, blockSize и
 *   уникальный fileId — любая перестановка/удаление/дублирование/усечение/
 *   кросс-файловая подстановка ломает tag или проверку segCount.
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
  FORMAT_VERSION_CHUNKED2,
  CHUNK_FILE_ID_LENGTH,
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

/** Длина заголовка чанкового контейнера 0x03: MAGIC(4)+version(1)+blockSize u32(4) = 9 */
export const CHUNKED_HEADER_LENGTH = HEADER_LENGTH + 4;
/**
 * Длина заголовка чанкового контейнера 0x04:
 * MAGIC(4)+version(1)+blockSize u32(4)+segCount u32(4)+fileId(16) = 29
 */
export const CHUNKED2_HEADER_LENGTH = HEADER_LENGTH + 4 + 4 + CHUNK_FILE_ID_LENGTH;
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

/** Проверяет наличие префикса MAGIC+version любого чанкового формата (0x03/0x04). */
function hasChunkedHeader(buf: Uint8Array): boolean {
  const v = magicVersion(buf);
  return v === FORMAT_VERSION_CHUNKED || v === FORMAT_VERSION_CHUNKED2;
}

/**
 * Возвращает версию чанкового контейнера по заголовку: 3 (0x03, legacy-чтение),
 * 4 (0x04, текущий) или null, если буфер — не чанковый контейнер.
 * Достаточно первых HEADER_LENGTH (5) байт.
 */
export function chunkedVersion(buf: Uint8Array): 3 | 4 | null {
  const v = magicVersion(buf);
  if (v === FORMAT_VERSION_CHUNKED) return 3;
  if (v === FORMAT_VERSION_CHUNKED2) return 4;
  return null;
}

/** Один расшифрованный сегмент чанкового контейнера: IV + body(ct‖tag). */
export interface ChunkSegment {
  iv: Uint8Array;
  body: Uint8Array;
}

/** Пишет u32 LE в буфер по смещению. */
function writeU32LE(buf: Uint8Array, off: number, value: number): void {
  buf[off] = value & 0xff;
  buf[off + 1] = (value >>> 8) & 0xff;
  buf[off + 2] = (value >>> 16) & 0xff;
  buf[off + 3] = (value >>> 24) & 0xff;
}

/**
 * Собирает заголовок ЛЕГАСИ-чанкового контейнера 0x03: MAGIC + 0x03 + blockSize.
 * Для записи новых файлов НЕ используется (движки пишут только 0x04) —
 * сохранён для генерации фикстур/тестов обратной совместимости.
 */
export function writeChunkedHeader(blockSize: number): Uint8Array {
  const out = new Uint8Array(CHUNKED_HEADER_LENGTH);
  out.set(MAGIC, 0);
  out[MAGIC_LENGTH] = FORMAT_VERSION_CHUNKED;
  writeU32LE(out, HEADER_LENGTH, blockSize);
  return out;
}

/**
 * Собирает заголовок чанкового контейнера 0x04:
 * MAGIC + 0x04 + blockSize u32 LE + segCount u32 LE + fileId(16).
 * Заголовок целиком входит в AAD каждого сегмента (см. chunkedSegmentAAD).
 */
export function writeChunked2Header(
  blockSize: number,
  segCount: number,
  fileId: Uint8Array
): Uint8Array {
  if (fileId.length !== CHUNK_FILE_ID_LENGTH) {
    throw new Error(`[format] fileId должен быть ${CHUNK_FILE_ID_LENGTH} байт`);
  }
  if (!Number.isInteger(segCount) || segCount < 0 || segCount > 0xffffffff) {
    throw new Error(`[format] Недопустимое число сегментов: ${segCount}`);
  }
  const out = new Uint8Array(CHUNKED2_HEADER_LENGTH);
  out.set(MAGIC, 0);
  out[MAGIC_LENGTH] = FORMAT_VERSION_CHUNKED2;
  writeU32LE(out, HEADER_LENGTH, blockSize);
  writeU32LE(out, HEADER_LENGTH + 4, segCount);
  out.set(fileId, HEADER_LENGTH + 8);
  return out;
}

/**
 * AAD сегмента №index формата 0x04: весь заголовок (29 байт) ‖ u32 LE(index).
 * Через AAD GCM-tag сегмента аутентифицирует его позицию, общее число
 * сегментов, blockSize и fileId файла.
 */
export function chunkedSegmentAAD(header: Uint8Array, index: number): Uint8Array {
  if (header.length !== CHUNKED2_HEADER_LENGTH) {
    throw new Error(
      `[format] AAD: заголовок 0x04 должен быть ${CHUNKED2_HEADER_LENGTH} байт`
    );
  }
  const out = new Uint8Array(CHUNKED2_HEADER_LENGTH + 4);
  out.set(header, 0);
  writeU32LE(out, CHUNKED2_HEADER_LENGTH, index);
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

/** Вычитывает сегменты [segLen][IV][ct‖tag] начиная с off до конца буфера. */
function readSegments(buf: Uint8Array, off: number): ChunkSegment[] {
  const segments: ChunkSegment[] = [];
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
  return segments;
}

/**
 * Разбирает целиком прочитанный ЛЕГАСИ-чанковый контейнер 0x03 на blockSize и
 * список сегментов (для расшифровки в памяти — используется WebCrypto на mobile
 * и Node-fallback при небольших файлах). Для реально потокового чтения на desktop
 * сегменты вычитываются по длинам без загрузки всего файла (см. NodeCryptoEngine).
 */
export function parseChunkedContainer(buf: Uint8Array): {
  blockSize: number;
  segments: ChunkSegment[];
} {
  if (chunkedVersion(buf) !== 3) {
    throw new Error("[format] Не контейнер v2-chunked 0x03 (неверный MAGIC/version)");
  }
  const blockSize = readU32LE(buf, HEADER_LENGTH);
  return { blockSize, segments: readSegments(buf, CHUNKED_HEADER_LENGTH) };
}

/**
 * Разбирает целиком прочитанный чанковый контейнер 0x04 СТРОГО:
 *   - число сегментов ДОЛЖНО совпадать с segCount из заголовка
 *     (усечение до N сегментов / до одного заголовка, дублирование и удаление
 *     сегментов детектируются ещё до расшифровки);
 *   - обрыв посреди сегмента/префикса — ошибка.
 * Возвращает также сырой заголовок (29 байт) для построения AAD.
 */
export function parseChunked2Container(buf: Uint8Array): {
  blockSize: number;
  segCount: number;
  header: Uint8Array;
  segments: ChunkSegment[];
} {
  if (chunkedVersion(buf) !== 4) {
    throw new Error("[format] Не контейнер v2-chunked 0x04 (неверный MAGIC/version)");
  }
  if (buf.length < CHUNKED2_HEADER_LENGTH) {
    throw new Error("[format] Чанковый контейнер 0x04 повреждён: обрезан заголовок");
  }
  const header = buf.subarray(0, CHUNKED2_HEADER_LENGTH);
  const blockSize = readU32LE(buf, HEADER_LENGTH);
  const segCount = readU32LE(buf, HEADER_LENGTH + 4);
  const segments = readSegments(buf, CHUNKED2_HEADER_LENGTH);
  if (segments.length !== segCount) {
    throw new Error(
      `[format] Чанковый контейнер 0x04 повреждён: сегментов ${segments.length}, ` +
        `в заголовке ${segCount} (усечение или лишние сегменты)`
    );
  }
  return { blockSize, segCount, header, segments };
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
  // Обе чанковые версии (0x03 legacy и 0x04 текущая) детектируются единым
  // тегом "v2-chunked" — потребителям важно "чанковый vs нет", а точная
  // версия доступна через chunkedVersion().
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
 *   - v2-chunked 0x03 (legacy): Σ(segLen − IV − tag) по префиксам длин сегментов;
 *     структура не самоописываемая, поэтому на битом хвосте возвращается
 *     частичная сумма (историческое поведение).
 *   - v2-chunked 0x04: то же суммирование, но СТРОГО — число сегментов сверяется
 *     с segCount из заголовка; усечённый/повреждённый контейнер даёт ОШИБКУ,
 *     а не молчаливую частичную сумму.
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

    if (chunkedVersion(buf) === 4) {
      // Строгий разбор: усечение/лишние данные → исключение (не частичная сумма).
      const { segments } = parseChunked2Container(buf);
      let plaintext = 0;
      for (const seg of segments) {
        plaintext += seg.body.length - GCM_TAG_LENGTH;
      }
      return plaintext;
    }

    // 0x03 (legacy): нестрогая частичная сумма — сохраняем прежнее поведение.
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

/** Возвращает true, если буфер — чанковый контейнер (0x03 или 0x04). */
export function isChunked(buf: Uint8Array): boolean {
  return hasChunkedHeader(buf);
}
