/**
 * Юнит-тесты для NodeCryptoEngine (формат v2).
 * Покрывают: деривацию ключа из email+password, шифрование/расшифровку
 * буферов, потоковое шифрование/расшифровку, обнуление ключа, граничные случаи.
 *
 * deriveKey теперь принимает (email, password): соль выводится из email.
 */

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as nodeCrypto from "crypto";
import { CryptoEngine } from "../src/crypto-engine";
import { HEADER_LENGTH, IV_LENGTH, GCM_TAG_LENGTH } from "../src/crypto/constants";

const TEST_EMAIL = "user@example.com";

// ─────────────────────────────────────────────
// Вспомогательные утилиты
// ─────────────────────────────────────────────

/** Создаёт временную директорию и возвращает функцию очистки */
function makeTempDir(): { dir: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shadowvault-test-"));
  return {
    dir,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

// ─────────────────────────────────────────────
// Тесты деривации ключа
// ─────────────────────────────────────────────

describe("CryptoEngine — deriveKey()", () => {
  it("должен дерировать ключ и переходить в состояние isUnlocked", async () => {
    const engine = new CryptoEngine();
    expect(engine.isUnlocked()).toBe(false);

    await engine.deriveKey(TEST_EMAIL, "correct-horse-battery-staple");
    expect(engine.isUnlocked()).toBe(true);

    engine.destroy();
  });

  it("одинаковый пароль → одинаковый ключ (детерминированность без соли)", async () => {
    const engine1 = new CryptoEngine();
    await engine1.deriveKey(TEST_EMAIL, "same-password");
    const plaintext = Buffer.from("hello world");
    const enc1 = engine1.encryptBuffer(plaintext);
    engine1.destroy();

    // Второй движок с тем же паролем должен расшифровать данные первого —
    // соль не нужна, ключ детерминирован
    const engine2 = new CryptoEngine();
    await engine2.deriveKey(TEST_EMAIL, "same-password");
    const dec = engine2.decryptBuffer(enc1);
    expect(dec.toString()).toBe("hello world");
    engine2.destroy();
  });

  it("разные пароли → невозможность расшифровки (неверный ключ)", async () => {
    const engine1 = new CryptoEngine();
    await engine1.deriveKey(TEST_EMAIL, "password-A");
    const enc = engine1.encryptBuffer(Buffer.from("secret data"));
    engine1.destroy();

    const engine2 = new CryptoEngine();
    await engine2.deriveKey(TEST_EMAIL, "password-B");
    expect(() => engine2.decryptBuffer(enc)).toThrow(
      /Расшифровка не удалась/
    );
    engine2.destroy();
  });
});

// ─────────────────────────────────────────────
// Тесты шифрования буферов
// ─────────────────────────────────────────────

describe("CryptoEngine — encryptBuffer() / decryptBuffer()", () => {
  let engine: CryptoEngine;

  beforeEach(async () => {
    engine = new CryptoEngine();
    await engine.deriveKey(TEST_EMAIL, "test-password-for-unit-tests");
  });

  afterEach(() => {
    engine.destroy();
  });

  it("шифрует и расшифровывает пустой буфер", () => {
    const empty = Buffer.alloc(0);
    const enc = engine.encryptBuffer(empty);
    const dec = engine.decryptBuffer(enc);
    expect(dec.length).toBe(0);
  });

  it("пустой plaintext → валидный v2-контейнер (не 0 байт)", () => {
    const enc = engine.encryptBuffer(Buffer.alloc(0));
    // 33 байта: MAGIC+ver(5)+IV(12)+tag(16)
    expect(enc.length).toBe(HEADER_LENGTH + IV_LENGTH + GCM_TAG_LENGTH);
    expect(enc.subarray(0, 4).toString("ascii")).toBe("SVLT");
  });

  it("legacy 0-байтный .enc трактуется как пустой plaintext (не ошибка)", () => {
    const dec = engine.decryptBuffer(Buffer.alloc(0));
    expect(dec.length).toBe(0);
  });

  it("шифрует и расшифровывает короткую строку", () => {
    const original = Buffer.from("Hello, ShadowVault!");
    const enc = engine.encryptBuffer(original);
    const dec = engine.decryptBuffer(enc);
    expect(dec.toString("utf8")).toBe("Hello, ShadowVault!");
  });

  it("шифрует и расшифровывает unicode (русский текст)", () => {
    const text = "Привет, мир! Это заметка в Obsidian. 🔐";
    const enc = engine.encryptBuffer(Buffer.from(text, "utf8"));
    const dec = engine.decryptBuffer(enc);
    expect(dec.toString("utf8")).toBe(text);
  });

  it("шифрует и расшифровывает буфер 1 МБ", () => {
    const bigBuf = nodeCrypto.randomBytes(1024 * 1024);
    const enc = engine.encryptBuffer(bigBuf);
    const dec = engine.decryptBuffer(enc);
    expect(dec.equals(bigBuf)).toBe(true);
  });

  it("каждый вызов encryptBuffer создаёт разный шифртекст (уникальный IV)", () => {
    const data = Buffer.from("same plaintext");
    const enc1 = engine.encryptBuffer(data);
    const enc2 = engine.encryptBuffer(data);
    // Первые 12 байт — IV, должны отличаться
    expect(enc1.subarray(0, 12).equals(enc2.subarray(0, 12))).toBe(false);
  });

  it("зашифрованный буфер v2 содержит корректный заголовок (MAGIC+version+IV+tag)", () => {
    const data = Buffer.from("test");
    const enc = engine.encryptBuffer(data);
    // Минимальный размер: header(5) + IV(12) + tag(16) + данные
    expect(enc.length).toBeGreaterThanOrEqual(HEADER_LENGTH + IV_LENGTH + GCM_TAG_LENGTH);
    // MAGIC "SVLT" + version 0x02
    expect(enc.subarray(0, 4).toString("ascii")).toBe("SVLT");
    expect(enc[4]).toBe(0x02);
  });

  it("повреждение tag (последние 16 байт) → ошибка расшифровки", () => {
    const enc = engine.encryptBuffer(Buffer.from("important data"));
    // Tag в формате v2 — последние 16 байт
    enc[enc.length - 1] = enc[enc.length - 1] ^ 0xff;
    expect(() => engine.decryptBuffer(enc)).toThrow(/Расшифровка не удалась/);
  });

  it("повреждение зашифрованных данных → ошибка расшифровки", () => {
    const enc = engine.encryptBuffer(Buffer.from("important data"));
    // Порча первого байта ciphertext (после header+IV)
    const off = HEADER_LENGTH + IV_LENGTH;
    enc[off] = enc[off] ^ 0xff;
    expect(() => engine.decryptBuffer(enc)).toThrow(/Расшифровка не удалась/);
  });

  it("слишком короткий буфер → явная ошибка о неверном формате", () => {
    const tooShort = Buffer.alloc(5);
    expect(() => engine.decryptBuffer(tooShort)).toThrow(/формат/);
  });

  it("бросает ошибку если ключ не загружен", () => {
    const locked = new CryptoEngine();
    expect(() => locked.encryptBuffer(Buffer.from("x"))).toThrow(/Ключ не загружен/);
    expect(() => locked.decryptBuffer(Buffer.from("x"))).toThrow(/Ключ не загружен/);
  });
});

// ─────────────────────────────────────────────
// Тесты потокового шифрования
// ─────────────────────────────────────────────

describe("CryptoEngine — encryptStream() / decryptStream()", () => {
  let engine: CryptoEngine;
  let tempDir: string;
  let cleanup: () => void;

  beforeEach(async () => {
    engine = new CryptoEngine();
    await engine.deriveKey(TEST_EMAIL, "stream-test-password");
    const tmp = makeTempDir();
    tempDir = tmp.dir;
    cleanup = tmp.cleanup;
  });

  afterEach(() => {
    engine.destroy();
    cleanup();
  });

  it("шифрует и расшифровывает текстовый файл потоком", async () => {
    const srcPath = path.join(tempDir, "note.md");
    const encPath = path.join(tempDir, "note.md.enc");
    const decPath = path.join(tempDir, "note.md.dec");

    const original = "# Заметка\n\nКонфиденциальный текст.";
    fs.writeFileSync(srcPath, original, "utf8");

    await engine.encryptStream(srcPath, encPath);
    await engine.decryptStream(encPath, decPath);

    const result = fs.readFileSync(decPath, "utf8");
    expect(result).toBe(original);
  });

  it("шифрует и расшифровывает бинарный файл потоком (1 МБ)", async () => {
    const srcPath = path.join(tempDir, "attachment.bin");
    const encPath = path.join(tempDir, "attachment.bin.enc");
    const decPath = path.join(tempDir, "attachment.bin.dec");

    const original = nodeCrypto.randomBytes(1024 * 1024);
    fs.writeFileSync(srcPath, original);

    await engine.encryptStream(srcPath, encPath);
    await engine.decryptStream(encPath, decPath);

    const result = fs.readFileSync(decPath);
    expect(result.equals(original)).toBe(true);
  });

  it("зашифрованный файл создаётся атомарно (нет .tmp после завершения)", async () => {
    const srcPath = path.join(tempDir, "data.txt");
    const encPath = path.join(tempDir, "data.txt.enc");
    fs.writeFileSync(srcPath, "atomic write test");

    await engine.encryptStream(srcPath, encPath);

    expect(fs.existsSync(encPath)).toBe(true);
    expect(fs.existsSync(encPath + ".tmp")).toBe(false);
  });

  it("зашифрованный файл v2 ровно на 33 байта больше оригинала (5 header + 12 IV + 16 tag)", async () => {
    const srcPath = path.join(tempDir, "small.txt");
    const encPath = path.join(tempDir, "small.txt.enc");
    const content = "tiny";
    fs.writeFileSync(srcPath, content);

    await engine.encryptStream(srcPath, encPath);

    const originalSize = fs.statSync(srcPath).size;
    const encSize = fs.statSync(encPath).size;
    expect(encSize).toBe(originalSize + HEADER_LENGTH + IV_LENGTH + GCM_TAG_LENGTH);
  });
});

// ─────────────────────────────────────────────
// Тесты уничтожения ключа
// ─────────────────────────────────────────────

describe("CryptoEngine — destroy()", () => {
  it("после destroy() isUnlocked() возвращает false", async () => {
    const engine = new CryptoEngine();
    await engine.deriveKey(TEST_EMAIL, "password");
    expect(engine.isUnlocked()).toBe(true);

    engine.destroy();
    expect(engine.isUnlocked()).toBe(false);
  });

  it("после destroy() encryptBuffer бросает ошибку", async () => {
    const engine = new CryptoEngine();
    await engine.deriveKey(TEST_EMAIL, "password");
    engine.destroy();
    expect(() => engine.encryptBuffer(Buffer.from("x"))).toThrow(/Ключ не загружен/);
  });

  it("повторный вызов destroy() не бросает ошибку", async () => {
    const engine = new CryptoEngine();
    await engine.deriveKey(TEST_EMAIL, "password");
    engine.destroy();
    expect(() => engine.destroy()).not.toThrow();
  });
});
