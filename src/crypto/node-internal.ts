/**
 * Внутренние константы для Node-реализации криптодвижка.
 * Не импортирует node:crypto — только собирает заголовок контейнера v2.
 */

import { MAGIC, FORMAT_VERSION } from "./constants";

/** Алгоритм AES-256-GCM в нотации node:crypto. */
export const ALGORITHM_NODE = "aes-256-gcm" as const;

/** Префикс контейнера v2: MAGIC "SVLT" + version 0x02 — как Buffer для Node-стримов. */
export const HEADER: Buffer = Buffer.concat([
  Buffer.from(MAGIC),
  Buffer.from([FORMAT_VERSION]),
]);
