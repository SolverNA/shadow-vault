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

/**
 * hex-строка → Uint8Array. Пустая строка → пустой массив.
 *
 * СТРОГАЯ валидация входа: нечётная длина или символы вне [0-9a-fA-F] —
 * явная ошибка формата. Без неё повреждённый verificationBlob/wrappedMaster
 * из data.json/localStorage тихо превращался в мусорные байты (NaN → 0)
 * и выглядел как «неверный пароль»/«неверный PIN» вместо ошибки данных.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(
      `[hex] Некорректная hex-строка: нечётная длина (${hex.length}) — данные повреждены`
    );
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(
      "[hex] Некорректная hex-строка: недопустимые символы (ожидаются только 0-9a-f) — данные повреждены"
    );
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
