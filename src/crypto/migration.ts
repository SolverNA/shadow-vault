/**
 * Ядро миграции legacy → v2 (ФАЗА 4), платформенно-нейтральное.
 *
 * Работает поверх буферов и уже разблокированного v2-движка (Node или Web).
 * Файловые операции (atomic rename и т.п.) — ответственность вызывающего слоя
 * (ShadowVaultManager на desktop, VirtualShadowManager/main на mobile), чтобы
 * этот модуль оставался MOBILE-SAFE (без node-импортов).
 *
 * Контракт безопасности (НЕ потерять данные):
 *   1. Уже мигрированные файлы (v2 по MAGIC) пропускаются → идемпотентность.
 *   2. legacy расшифровывается trial-decrypt'ом (node-layout, затем web).
 *   3. Перешифровка в v2 новым ключом.
 *   4. ОБЯЗАТЕЛЬНЫЙ round-trip verify: новый v2-буфер расшифровывается обратно
 *      и побайтно сравнивается с исходным plaintext ПЕРЕД тем, как вызывающий
 *      слой заменит файл. Если verify не прошёл — бросаем, файл НЕ заменяется.
 */

import { detectFormat } from "./format";
import { legacyDecrypt, LegacyVariant } from "./legacy";

/** Минимальный интерфейс v2-движка, нужный мигратору. */
export interface V2Engine {
  encryptBuffer(data: Uint8Array | ArrayBuffer | Buffer): unknown;
  decryptBuffer(data: Uint8Array | ArrayBuffer | Buffer): unknown;
}

function toU8(x: unknown): Uint8Array {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  throw new Error("[migration] неподдерживаемый тип результата движка");
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Результат миграции одного буфера. */
export type MigrateBufferResult =
  | { status: "skipped-v2" }
  | { status: "migrated"; v2: Uint8Array; variant: LegacyVariant };

/**
 * Мигрирует один зашифрованный буфер legacy → v2 с round-trip verify.
 *
 * @param enc      содержимое .enc файла
 * @param password пароль (для деривации СТАРОГО legacy-ключа)
 * @param engine   v2-движок с УЖЕ загруженным новым ключом (email+password)
 * @param hint     подсказка варианта legacy для ускорения (опц.)
 * @returns        {status:"skipped-v2"} если уже v2, иначе новый v2-буфер
 * @throws         если legacy-decrypt не удался (неверный пароль) или round-trip
 *                 verify не сошёлся (тогда файл НЕЛЬЗЯ заменять)
 */
export async function migrateBuffer(
  enc: Uint8Array,
  password: string,
  engine: V2Engine,
  hint?: LegacyVariant
): Promise<MigrateBufferResult> {
  // Идемпотентность: уже мигрированный файл (v2 по MAGIC) не трогаем.
  if (detectFormat(enc) === "v2") {
    return { status: "skipped-v2" };
  }

  // 1. Расшифровываем legacy (trial-decrypt). Бросит при неверном пароле.
  const { plaintext, variant } = await legacyDecrypt(enc, password, hint);

  // 2. Перешифровываем новым v2-ключом.
  const v2 = toU8(await Promise.resolve(engine.encryptBuffer(plaintext)));

  // 3. Round-trip verify ПЕРЕД заменой: v2 должен расшифроваться в тот же plaintext.
  const back = toU8(await Promise.resolve(engine.decryptBuffer(v2)));
  if (!bytesEqual(back, plaintext)) {
    throw new Error(
      "[migration] round-trip verify не прошёл: новый v2-буфер не " +
        "расшифровывается в исходный plaintext — файл НЕ заменён"
    );
  }

  return { status: "migrated", v2, variant };
}

/**
 * Проверяет, что введённый пароль верен для legacy-хранилища, пробуя
 * trial-decrypt одного образца .enc. Используется когда verificationBlob
 * отсутствует (старое хранилище без блоба).
 *
 * @returns распознанный legacy-вариант (можно использовать как hint),
 *          либо null если sample пустой/не дешифруется этим паролем.
 */
export async function probeLegacyPassword(
  sampleEnc: Uint8Array,
  password: string
): Promise<LegacyVariant | null> {
  // v2-образец означает, что хранилище уже мигрировано — не legacy.
  if (detectFormat(sampleEnc) === "v2") return null;
  try {
    const { variant } = await legacyDecrypt(sampleEnc, password);
    return variant;
  } catch {
    return null;
  }
}
