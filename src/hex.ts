/**
 * Кодирование байт ↔ hex-строка. Единственный источник правды —
 * чтобы не дублировать одну и ту же логику в auth-service/main/pin-store.
 *
 * MOBILE-SAFE: чистые функции без top-level node-импортов, работают
 * на обеих платформах.
 */

/** Uint8Array → hex-строка нижнего регистра (по 2 символа на байт). */
export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

/** hex-строка → Uint8Array. Длина строки должна быть чётной. */
export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
