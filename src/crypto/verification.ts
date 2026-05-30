/**
 * Verification blob — проверка правильности пароля до расшифровки хранилища.
 *
 * createVerificationBlob: шифрует известную константу в формат v2 → base64.
 * verifyPassword: расшифровывает и сравнивает с константой → boolean
 *                 (без исключений наружу при неверном пароле).
 *
 * Работает поверх любого движка (Node/Web): шифрование/расшифровка
 * приводятся к асинхронному виду через Promise.resolve, чтобы покрыть
 * и синхронный Node API, и асинхронный Web API.
 */

import { VERIFICATION_CONSTANT } from "./constants";

const utf8 = new TextEncoder();
const dec = new TextDecoder();

/** Минимальный набор методов движка, нужный для верификации. */
interface BlobEngine {
  encryptBuffer(data: Uint8Array | ArrayBuffer | Buffer): unknown;
  decryptBuffer(data: Uint8Array | ArrayBuffer | Buffer): unknown;
}

function toUint8(x: unknown): Uint8Array {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  // Buffer — это Uint8Array, уже покрыто выше
  throw new Error("[verification] неподдерживаемый тип результата движка");
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Создаёт верификационный блоб: шифрует VERIFICATION_CONSTANT в v2 → base64.
 */
export async function createVerificationBlob(engine: BlobEngine): Promise<string> {
  const plaintext = utf8.encode(VERIFICATION_CONSTANT);
  const enc = await Promise.resolve(engine.encryptBuffer(plaintext));
  return bytesToBase64(toUint8(enc));
}

/**
 * Проверяет пароль через верификационный блоб.
 * Возвращает true/false, исключения наружу не пробрасывает.
 */
export async function verifyPassword(
  engine: BlobEngine,
  blobBase64: string
): Promise<boolean> {
  try {
    const container = base64ToBytes(blobBase64);
    const decrypted = await Promise.resolve(engine.decryptBuffer(container));
    return dec.decode(toUint8(decrypted)) === VERIFICATION_CONSTANT;
  } catch {
    return false;
  }
}
