/**
 * Единые криптопараметры ShadowVault (ФАЗА 1 — единое криптоядро).
 *
 * ВАЖНО: эти константы определяют формат файлов и деривацию ключа.
 * И NodeCryptoEngine, и WebCryptoEngine ОБЯЗАНЫ использовать ровно эти значения,
 * иначе нарушится байт-в-байт совместимость между десктопом и мобильными.
 *
 * Менять только с миграцией существующих .enc файлов.
 */

/** Магия формата v2 — ASCII "SVLT" (ShadowVault) */
export const MAGIC = new Uint8Array([0x53, 0x56, 0x4c, 0x54]); // "SVLT"
export const MAGIC_LENGTH = 4;

/** Версия формата контейнера (цельный v2: весь файл — один AES-GCM сегмент) */
export const FORMAT_VERSION = 0x02;
export const VERSION_LENGTH = 1;

/**
 * Версия чанкового под-формата (v2-chunked): файл разбит на независимые
 * AES-GCM сегменты с собственным IV и tag. Нужен для реально потоковой
 * обработки больших вложений без буферизации всего файла в RAM.
 *
 * Layout (см. crypto/format.ts):
 *   [MAGIC "SVLT"(4)] [version 0x03(1)] [blockSize u32 LE(4)]
 *   затем последовательность сегментов, каждый:
 *     [segLen u32 LE(4)] [IV(12)] [ciphertext‖tag(16 в конце)]
 *   где segLen = длина (IV + ciphertext + tag) данного сегмента.
 *
 * Каждый сегмент шифрует ровно blockSize байт plaintext (последний — остаток).
 * Mobile и desktop ОБА обязаны уметь ЧИТАТЬ этот формат (writeChunkedHeader
 * пишет пока только desktop). Это сохраняет кросс-совместимость.
 */
export const FORMAT_VERSION_CHUNKED = 0x03;

/**
 * Размер блока чанкового формата по умолчанию — 4 МБ plaintext на сегмент.
 * Баланс: достаточно крупный, чтобы overhead заголовков сегментов был мал
 * (~32 байта на 4 МБ), и достаточно мелкий, чтобы пиковая память была ограничена.
 */
export const CHUNK_BLOCK_SIZE = 4 * 1024 * 1024;

/**
 * Порог «большого файла»: файлы больше этого размера на DESKTOP пишутся в
 * чанковом под-формате (0x03) потоково. Меньшие — цельным v2 (0x02), чтобы
 * не менять поведение для типичных заметок.
 */
export const CHUNKED_THRESHOLD = 4 * 1024 * 1024;

/** Длина префикса заголовка: MAGIC(4) + version(1) */
export const HEADER_LENGTH = MAGIC_LENGTH + VERSION_LENGTH;

/** Параметры AES-GCM */
export const IV_LENGTH = 12; // байт, рекомендация NIST для GCM
export const GCM_TAG_LENGTH = 16; // байт, 128-битный тег аутентификации
export const KEY_LENGTH = 32; // байт = AES-256

/**
 * Параметры PBKDF2 — ОДИНАКОВЫ на Node и WebCrypto.
 * 600000 итераций SHA-512 — баланс безопасности и скорости (OWASP-уровень).
 */
export const PBKDF2_ITERATIONS = 600_000;
export const PBKDF2_KEY_LENGTH = KEY_LENGTH; // 32 байта (256 бит)
/** Имя hash для Node ("sha512") и WebCrypto ("SHA-512") выводится отдельно ниже */
export const PBKDF2_HASH_NODE = "sha512" as const;
export const PBKDF2_HASH_WEB = "SHA-512" as const;

/**
 * Доменная строка соли v2.
 * salt = SHA-256( utf8(normalize(email)) ‖ utf8(SALT_DOMAIN) )
 */
export const SALT_DOMAIN = "shadow-vault:v2";

/** Константа верификационного блоба v2 */
export const VERIFICATION_CONSTANT = "shadow-vault-verify-v2";

/**
 * Маркеры legacy-форматов для detectFormat().
 * legacy-node: [IV(12)][AuthTag(16)][ciphertext]  (старый crypto-engine.ts)
 * legacy-web:  [IV(12)][ciphertext‖tag]            (старый web-crypto-engine.ts)
 * У них нет MAGIC-префикса, поэтому детект эвристический (см. detectFormat).
 */

/**
 * Параметры СТАРОГО формата шифрования (legacy, до ФАЗЫ 1).
 *
 * Значения сверены БАЙТ-В-БАЙТ со старым кодом из git-истории
 * (commit 0a66e2e: src/crypto-engine.ts и src/web-crypto-engine.ts).
 * НЕ МЕНЯТЬ — от них зависит расшифровка уже существующих legacy-хранилищ.
 *
 * Общее для обоих legacy-вариантов:
 *   - AES-256-GCM, IV 12 байт, GCM-tag 16 байт.
 *   - PBKDF2 поверх пароля с фиксированной доменной СОЛЬЮ "shadow-vault:v1"
 *     (UTF-8), без участия email. Хэш SHA-512.
 *   - НЕТ MAGIC-префикса.
 *
 * Различия:
 *   legacy-node: layout [IV(12)][AuthTag(16)][ciphertext], 310000 итераций.
 *   legacy-web:  layout [IV(12)][ciphertext‖tag(16 в конце)], 600000 итераций.
 */
export const LEGACY_SALT_DOMAIN = "shadow-vault:v1";
export const LEGACY_PBKDF2_ITERATIONS_NODE = 310_000;
export const LEGACY_PBKDF2_ITERATIONS_WEB = 600_000;
