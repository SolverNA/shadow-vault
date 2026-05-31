/**
 * Внутренние константы для Node-реализации криптодвижка.
 * Не импортирует node:crypto — только собирает заголовок контейнера v2.
 *
 * MOBILE-SAFE: этот модуль попадает в mobile-цепочку загрузки
 * (crypto-engine → factory → auth-service/init-modal), поэтому НЕ должен
 * содержать НИКАКИХ top-level node-вызовов, в том числе глобального Buffer.
 * Заголовок собираем как Uint8Array — он валиден и для Node-стримов
 * (writeStream.write принимает Uint8Array), и для конкатенации через Buffer.concat.
 */

import { MAGIC, FORMAT_VERSION } from "./constants";

/** Алгоритм AES-256-GCM в нотации node:crypto. */
export const ALGORITHM_NODE = "aes-256-gcm" as const;

/**
 * Префикс контейнера v2: MAGIC "SVLT" + version 0x02.
 * Uint8Array (без top-level Buffer) — безопасно для mobile-загрузки.
 */
export const HEADER: Uint8Array = new Uint8Array([
  MAGIC[0],
  MAGIC[1],
  MAGIC[2],
  MAGIC[3],
  FORMAT_VERSION,
]);
