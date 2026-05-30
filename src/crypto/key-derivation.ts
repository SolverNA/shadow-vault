/**
 * Деривация мастер-ключа ShadowVault (единая для всех платформ, ФАЗА 1).
 *
 *   normalize(email) = email.trim().toLowerCase()
 *   salt      = SHA-256( utf8(normalize(email)) ‖ utf8("shadow-vault:v2") )  → 32 байта
 *   masterKey = PBKDF2( password, salt, 600000, 32, SHA-512 )                 → 32 байта
 *
 * Реализация идёт через WebCrypto SubtleCrypto, который доступен и в браузере,
 * и в Node 16+ (через globalThis.crypto или node:crypto.webcrypto). Это
 * гарантирует БАЙТ-В-БАЙТ одинаковый ключ на десктопе и мобильных.
 */

import {
  PBKDF2_ITERATIONS,
  PBKDF2_KEY_LENGTH,
  PBKDF2_HASH_WEB,
  SALT_DOMAIN,
} from "./constants";
import { getSubtle } from "./platform";

const utf8 = new TextEncoder();

/** Нормализация email: trim + lowercase. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Конкатенация Uint8Array. */
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Вычисляет соль из email:
 *   salt = SHA-256( utf8(normalize(email)) ‖ utf8(SALT_DOMAIN) )
 */
export async function deriveSalt(email: string): Promise<Uint8Array> {
  const subtle = getSubtle();
  const input = concatBytes(
    utf8.encode(normalizeEmail(email)),
    utf8.encode(SALT_DOMAIN)
  );
  const digest = await subtle.digest("SHA-256", input);
  return new Uint8Array(digest);
}

/**
 * Деривирует мастер-ключ (сырые 32 байта) из email+password.
 * Возвращает Uint8Array, чтобы обе реализации движков могли импортировать
 * его в свой формат ключа (CryptoKey для WebCrypto, Buffer для Node).
 */
export async function deriveMasterKey(
  email: string,
  password: string
): Promise<Uint8Array> {
  const subtle = getSubtle();
  const salt = await deriveSalt(email);

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
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH_WEB,
    },
    keyMaterial,
    PBKDF2_KEY_LENGTH * 8
  );

  return new Uint8Array(bits);
}
