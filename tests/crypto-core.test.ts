/**
 * Тесты единого криптоядра (ФАЗА 1).
 *
 * Ключевая гарантия — кроссплатформенность: NodeCryptoEngine и WebCryptoEngine
 * дают БАЙТ-В-БАЙТ совместимый формат v2 и одинаковую деривацию ключа.
 * Кросс-тест: то, что зашифровал один движок, расшифровывает другой.
 *
 * В Node тестовой среде crypto.subtle доступен через globalThis.crypto,
 * поэтому обе реализации работают в одном процессе.
 */

import { describe, it, expect } from "@jest/globals";
import { NodeCryptoEngine } from "../src/crypto-engine";
import { WebCryptoEngine } from "../src/web-crypto-engine";
import { deriveMasterKey, deriveSalt, normalizeEmail } from "../src/crypto/key-derivation";
import { detectFormat, isV2 } from "../src/crypto/format";
import { createVerificationBlob, verifyPassword } from "../src/crypto/verification";
import { bytesToHex, hexToBytes } from "../src/hex";
import {
  MAGIC,
  FORMAT_VERSION,
  IV_LENGTH,
  GCM_TAG_LENGTH,
  HEADER_LENGTH,
} from "../src/crypto/constants";

const EMAIL = "Alice@Example.com";
const PASSWORD = "correct horse battery staple";

function u8(x: ArrayBuffer | Uint8Array | Buffer): Uint8Array {
  if (x instanceof Uint8Array) return x;
  return new Uint8Array(x);
}

// ─────────────────────────────────────────────
// Деривация ключа
// ─────────────────────────────────────────────

describe("key-derivation", () => {
  it("normalizeEmail: trim + lowercase", () => {
    expect(normalizeEmail("  Alice@Example.COM  ")).toBe("alice@example.com");
  });

  it("salt детерминирован и равен 32 байтам", async () => {
    const s1 = await deriveSalt(EMAIL);
    const s2 = await deriveSalt("  alice@example.com ");
    expect(s1.length).toBe(32);
    expect(Buffer.from(s1).equals(Buffer.from(s2))).toBe(true); // нормализация
  });

  it("одинаковые email+password → одинаковый ключ", async () => {
    const k1 = await deriveMasterKey(EMAIL, PASSWORD);
    const k2 = await deriveMasterKey(EMAIL, PASSWORD);
    expect(k1.length).toBe(32);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
  });

  it("разные email → разные ключи", async () => {
    const k1 = await deriveMasterKey("a@example.com", PASSWORD);
    const k2 = await deriveMasterKey("b@example.com", PASSWORD);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });

  it("разные пароли → разные ключи", async () => {
    const k1 = await deriveMasterKey(EMAIL, "pw-A");
    const k2 = await deriveMasterKey(EMAIL, "pw-B");
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });
});

// ─────────────────────────────────────────────
// hex: bytesToHex / hexToBytes
// ─────────────────────────────────────────────

describe("hex: bytesToHex/hexToBytes", () => {
  it("round-trip: bytesToHex → hexToBytes возвращает исходные байты", () => {
    const bytes = new Uint8Array([0, 1, 15, 16, 127, 128, 255]);
    const hex = bytesToHex(bytes);
    expect(hex).toBe("00010f107f80ff");
    expect(Buffer.from(hexToBytes(hex)).equals(Buffer.from(bytes))).toBe(true);
  });

  it("верхний регистр (A-F) принимается", () => {
    expect(Buffer.from(hexToBytes("DEADBEEF")).equals(
      Buffer.from([0xde, 0xad, 0xbe, 0xef])
    )).toBe(true);
  });

  it("пустая строка → пустой массив (как раньше)", () => {
    expect(hexToBytes("").length).toBe(0);
  });

  it("нечётная длина → явная ошибка формата (не молчаливый обрезанный байт)", () => {
    expect(() => hexToBytes("abc")).toThrow(/нечётная длина/);
    expect(() => hexToBytes("0")).toThrow(/нечётная длина/);
  });

  it("не-hex символы → явная ошибка формата (не NaN → 0)", () => {
    expect(() => hexToBytes("zzzz")).toThrow(/недопустимые символы/);
    expect(() => hexToBytes("12g4")).toThrow(/недопустимые символы/);
    expect(() => hexToBytes("de.dad")).toThrow(/недопустимые символы/);
  });
});

// ─────────────────────────────────────────────
// detectFormat
// ─────────────────────────────────────────────

describe("detectFormat", () => {
  it("распознаёт контейнер v2", async () => {
    const e = new NodeCryptoEngine();
    await e.deriveKey(EMAIL, PASSWORD);
    const enc = e.encryptBuffer(Buffer.from("hi"));
    expect(detectFormat(enc)).toBe("v2");
    expect(isV2(enc)).toBe(true);
    e.destroy();
  });

  it("буфер без MAGIC, но достаточной длины → legacy-node", () => {
    const legacy = new Uint8Array(IV_LENGTH + GCM_TAG_LENGTH + 4); // без префикса
    expect(detectFormat(legacy)).toBe("legacy-node");
  });

  it("слишком короткий буфер → unknown", () => {
    expect(detectFormat(new Uint8Array(5))).toBe("unknown");
  });

  it("header содержит MAGIC SVLT + version 0x02", async () => {
    const e = new NodeCryptoEngine();
    await e.deriveKey(EMAIL, PASSWORD);
    const enc = e.encryptBuffer(Buffer.from("x"));
    for (let i = 0; i < MAGIC.length; i++) expect(enc[i]).toBe(MAGIC[i]);
    expect(enc[4]).toBe(FORMAT_VERSION);
    e.destroy();
  });
});

// ─────────────────────────────────────────────
// Round-trip обеих реализаций
// ─────────────────────────────────────────────

describe("round-trip", () => {
  it("NodeCryptoEngine encrypt → decrypt", async () => {
    const e = new NodeCryptoEngine();
    await e.deriveKey(EMAIL, PASSWORD);
    const enc = e.encryptBuffer(Buffer.from("узел node 🔐"));
    expect(e.decryptBuffer(enc).toString("utf8")).toBe("узел node 🔐");
    e.destroy();
  });

  it("WebCryptoEngine encrypt → decrypt", async () => {
    const e = new WebCryptoEngine();
    await e.deriveKey(EMAIL, PASSWORD);
    const enc = await e.encryptText("веб web 🔐");
    expect(await e.decryptText(enc)).toBe("веб web 🔐");
    e.destroy();
  });
});

// ─────────────────────────────────────────────
// КРОСС-ТЕСТ кроссплатформенности
// ─────────────────────────────────────────────

describe("кроссплатформенная совместимость Node ↔ Web", () => {
  it("Web шифрует → Node расшифровывает", async () => {
    const web = new WebCryptoEngine();
    await web.deriveKey(EMAIL, PASSWORD);
    const node = new NodeCryptoEngine();
    await node.deriveKey(EMAIL, PASSWORD);

    const original = "Кросс-платформенная заметка ✅";
    const enc = await web.encryptText(original);
    const dec = node.decryptBuffer(Buffer.from(u8(enc)));
    expect(dec.toString("utf8")).toBe(original);

    web.destroy();
    node.destroy();
  });

  it("Node шифрует → Web расшифровывает", async () => {
    const node = new NodeCryptoEngine();
    await node.deriveKey(EMAIL, PASSWORD);
    const web = new WebCryptoEngine();
    await web.deriveKey(EMAIL, PASSWORD);

    const original = "Заметка с десктопа, читается на телефоне 📱";
    const enc = node.encryptBuffer(Buffer.from(original, "utf8"));
    const dec = await web.decryptText(enc);
    expect(dec).toBe(original);

    node.destroy();
    web.destroy();
  });

  it("оба движка дают идентичный layout заголовка для одних данных", async () => {
    const node = new NodeCryptoEngine();
    await node.deriveKey(EMAIL, PASSWORD);
    const web = new WebCryptoEngine();
    await web.deriveKey(EMAIL, PASSWORD);

    const nEnc = u8(node.encryptBuffer(Buffer.from("abc")));
    const wEnc = u8(await web.encryptText("abc"));

    // Заголовок (MAGIC+version) идентичен
    expect(Buffer.from(nEnc.subarray(0, HEADER_LENGTH)).equals(Buffer.from(wEnc.subarray(0, HEADER_LENGTH)))).toBe(true);
    // Полная длина совпадает (IV случаен, но размеры равны)
    expect(nEnc.length).toBe(wEnc.length);

    node.destroy();
    web.destroy();
  });
});

// ─────────────────────────────────────────────
// Verification blob
// ─────────────────────────────────────────────

describe("verification blob", () => {
  it("createVerificationBlob → verifyPassword true при верном ключе (Node)", async () => {
    const e = new NodeCryptoEngine();
    await e.deriveKey(EMAIL, PASSWORD);
    const blob = await createVerificationBlob(e);
    expect(await verifyPassword(e, blob)).toBe(true);
    e.destroy();
  });

  it("verifyPassword false при неверном ключе (без исключений)", async () => {
    const right = new NodeCryptoEngine();
    await right.deriveKey(EMAIL, PASSWORD);
    const blob = await createVerificationBlob(right);
    right.destroy();

    const wrong = new NodeCryptoEngine();
    await wrong.deriveKey(EMAIL, "another-password");
    expect(await verifyPassword(wrong, blob)).toBe(false);
    wrong.destroy();
  });

  it("блоб, созданный Node, проверяется Web-движком (кроссплатформенно)", async () => {
    const node = new NodeCryptoEngine();
    await node.deriveKey(EMAIL, PASSWORD);
    const blob = await createVerificationBlob(node);
    node.destroy();

    const web = new WebCryptoEngine();
    await web.deriveKey(EMAIL, PASSWORD);
    expect(await verifyPassword(web, blob)).toBe(true);
    web.destroy();
  });

  it("verifyPassword false на мусорном blob", async () => {
    const e = new NodeCryptoEngine();
    await e.deriveKey(EMAIL, PASSWORD);
    expect(await verifyPassword(e, "bm90LWEtdmFsaWQtYmxvYg==")).toBe(false);
    e.destroy();
  });
});
