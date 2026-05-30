/**
 * Расшифровка СТАРОГО формата ShadowVault (legacy) для миграции в v2 (ФАЗА 4).
 *
 * Старых формата два, и по содержимому буфера их надёжно НЕ различить (оба
 * начинаются с 12 байт IV и содержат 16-байтный GCM-tag, отличается лишь
 * позиция tag и число PBKDF2-итераций). Поэтому применяется trial-decrypt:
 * сначала пробуем legacy-node layout/params, при провале GCM-аутентификации —
 * legacy-web. Если оба не сработали — пароль неверный или файл повреждён.
 *
 * MOBILE-SAFE: модуль НЕ импортирует node:crypto/fs на верхнем уровне.
 * Вся криптография идёт через SubtleCrypto (getSubtle()), доступный и в
 * браузере/mobile, и в Node 16+. Это тот же путь, что использует
 * key-derivation.ts — гарантирует одинаковое поведение на всех платформах.
 *
 * Параметры legacy сверены байт-в-байт со старым кодом (commit 0a66e2e):
 *   crypto-engine.ts      → legacy-node
 *   web-crypto-engine.ts  → legacy-web
 */

import {
  IV_LENGTH,
  GCM_TAG_LENGTH,
  KEY_LENGTH,
  LEGACY_SALT_DOMAIN,
  LEGACY_PBKDF2_ITERATIONS_NODE,
  LEGACY_PBKDF2_ITERATIONS_WEB,
} from "./constants";
import { getSubtle } from "./platform";

const utf8 = new TextEncoder();

/** Распознанный вариант старого формата. */
export type LegacyVariant = "legacy-node" | "legacy-web";

/** Результат успешного trial-decrypt одного legacy-буфера. */
export interface LegacyDecryptResult {
  /** Расшифрованный plaintext. */
  plaintext: Uint8Array;
  /** Каким из двух legacy-вариантов файл оказался зашифрован. */
  variant: LegacyVariant;
}

/**
 * Деривирует legacy-ключ из пароля.
 * salt = utf8("shadow-vault:v1") (фиксированная константа, БЕЗ email),
 * masterKey = PBKDF2(password, salt, iterations, SHA-512, 32 байта).
 */
async function deriveLegacyKey(
  password: string,
  iterations: number
): Promise<CryptoKey> {
  const subtle = getSubtle();
  const keyMaterial = await subtle.importKey(
    "raw",
    utf8.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: utf8.encode(LEGACY_SALT_DOMAIN),
      iterations,
      hash: "SHA-512",
    },
    keyMaterial,
    KEY_LENGTH * 8
  );
  return subtle.importKey(
    "raw",
    new Uint8Array(bits),
    { name: "AES-GCM", length: KEY_LENGTH * 8 },
    false,
    ["decrypt"]
  );
}

/**
 * Пытается расшифровать буфер как legacy-node:
 *   layout [IV(12)][AuthTag(16)][ciphertext], PBKDF2 310000.
 * WebCrypto AES-GCM ожидает ciphertext‖tag, поэтому переставляем tag в конец.
 * Возвращает plaintext либо null при провале GCM-аутентификации.
 */
async function tryLegacyNode(
  buf: Uint8Array,
  password: string
): Promise<Uint8Array | null> {
  if (buf.length < IV_LENGTH + GCM_TAG_LENGTH) return null;
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + GCM_TAG_LENGTH);
  const ciphertext = buf.subarray(IV_LENGTH + GCM_TAG_LENGTH);

  // WebCrypto принимает ciphertext‖tag — собираем body в этом порядке.
  const body = new Uint8Array(ciphertext.length + tag.length);
  body.set(ciphertext, 0);
  body.set(tag, ciphertext.length);

  try {
    const key = await deriveLegacyKey(password, LEGACY_PBKDF2_ITERATIONS_NODE);
    const subtle = getSubtle();
    const plain = await subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH * 8 },
      key,
      body
    );
    return new Uint8Array(plain);
  } catch {
    return null; // GCM auth fail → не legacy-node (или неверный пароль)
  }
}

/**
 * Пытается расшифровать буфер как legacy-web:
 *   layout [IV(12)][ciphertext‖tag(16 в конце)], PBKDF2 600000.
 * Возвращает plaintext либо null при провале GCM-аутентификации.
 */
async function tryLegacyWeb(
  buf: Uint8Array,
  password: string
): Promise<Uint8Array | null> {
  if (buf.length < IV_LENGTH + GCM_TAG_LENGTH) return null;
  const iv = buf.subarray(0, IV_LENGTH);
  const body = buf.subarray(IV_LENGTH); // ciphertext‖tag

  try {
    const key = await deriveLegacyKey(password, LEGACY_PBKDF2_ITERATIONS_WEB);
    const subtle = getSubtle();
    const plain = await subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH * 8 },
      key,
      body
    );
    return new Uint8Array(plain);
  } catch {
    return null;
  }
}

/**
 * Расшифровывает legacy-буфер trial-decrypt'ом: сначала node-вариант,
 * затем web-вариант. Пустой буфер (0 байт) — валидный пустой файл legacy.
 *
 * @throws Error если ни один вариант не подошёл (неверный пароль / повреждение).
 */
export async function legacyDecrypt(
  buf: Uint8Array,
  password: string,
  hint?: LegacyVariant
): Promise<LegacyDecryptResult> {
  // Пустой файл: старый encryptAllExisting писал нулевой .enc для пустых
  // заметок. Расшифровка пустого даёт пустой plaintext.
  if (buf.length === 0) {
    return { plaintext: new Uint8Array(0), variant: "legacy-node" };
  }

  // hint ускоряет bulk-миграцию: первый успешный вариант обычно и для остальных.
  const order: LegacyVariant[] =
    hint === "legacy-web" ? ["legacy-web", "legacy-node"] : ["legacy-node", "legacy-web"];

  for (const variant of order) {
    const plain =
      variant === "legacy-node"
        ? await tryLegacyNode(buf, password)
        : await tryLegacyWeb(buf, password);
    if (plain) return { plaintext: plain, variant };
  }

  throw new Error(
    "[legacy] Расшифровка не удалась: неверный пароль или файл повреждён " +
      "(GCM auth fail для обоих legacy-вариантов)"
  );
}
