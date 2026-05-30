/**
 * Контейнер зашифрованного файла v2 и детектор форматов.
 *
 * Формат v2:
 *   [MAGIC "SVLT" (4)] [version 0x02 (1)] [IV (12)] [ciphertext‖GCM-tag(16 в конце)]
 *
 * Этот layout одинаков для Node и WebCrypto:
 *   - WebCrypto AES-GCM сам возвращает ciphertext‖tag;
 *   - в Node ciphertext и getAuthTag() склеиваются в том же порядке.
 */

import {
  MAGIC,
  MAGIC_LENGTH,
  FORMAT_VERSION,
  HEADER_LENGTH,
  IV_LENGTH,
  GCM_TAG_LENGTH,
} from "./constants";

export type EncryptedFormat = "v2" | "legacy-node" | "legacy-web" | "unknown";

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

/** Проверяет наличие префикса MAGIC+version v2. */
function hasV2Header(buf: Uint8Array): boolean {
  if (buf.length < HEADER_LENGTH) return false;
  for (let i = 0; i < MAGIC_LENGTH; i++) {
    if (buf[i] !== MAGIC[i]) return false;
  }
  return buf[MAGIC_LENGTH] === FORMAT_VERSION;
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

  // legacy-layout: минимум IV(12) + tag(16)
  if (buf.length >= IV_LENGTH + GCM_TAG_LENGTH) {
    return "legacy-node";
  }
  return "unknown";
}

/** Возвращает true, если буфер — контейнер v2. */
export function isV2(buf: Uint8Array): boolean {
  return hasV2Header(buf);
}
