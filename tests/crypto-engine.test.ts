/**
 * Юнит-тесты для CryptoEngine.
 * Покрывают: деривацию ключа, шифрование/расшифровку буферов,
 * потоковое шифрование/расшифровку, обнуление ключа, граничные случаи.
 *
 * Соль не используется: ключ деривируется только из пароля и фиксированной
 * доменной константы внутри CryptoEngine.
 */

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as nodeCrypto from "crypto";
import { CryptoEngine } from "../src/crypto-engine";

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

    await engine.deriveKey("correct-horse-battery-staple");
    expect(engine.isUnlocked()).toBe(true);

    engine.destroy();
  });

  it("одинаковый пароль → одинаковый ключ (детерминированность без соли)", async () => {
    const engine1 = new CryptoEngine();
    await engine1.deriveKey("same-password");
    const plaintext = Buffer.from("hello world");
    const enc1 = engine1.encryptBuffer(plaintext);
    engine1.destroy();

    // Второй движок с тем же паролем должен расшифровать данные первого —
    // соль не нужна, ключ детерминирован
    const engine2 = new CryptoEngine();
    await engine2.deriveKey("same-password");
    const dec = engine2.decryptBuffer(enc1);
    expect(dec.toString()).toBe("hello world");
    engine2.destroy();
  });

  it("разные пароли → невозможность расшифровки (неверный ключ)", async () => {
    const engine1 = new CryptoEngine();
    await engine1.deriveKey("password-A");
    const enc = engine1.encryptBuffer(Buffer.from("secret data"));
    engine1.destroy();

    const engine2 = new CryptoEngine();
    await engine2.deriveKey("password-B");
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
    await engine.deriveKey("test-password-for-unit-tests");
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

  it("зашифрованный буфер содержит корректный заголовок (IV + AuthTag)", () => {
    const data = Buffer.from("test");
    const enc = engine.encryptBuffer(data);
    // Минимальный размер: 12 (IV) + 16 (AuthTag) + 0 или более байт данных
    expect(enc.length).toBeGreaterThanOrEqual(12 + 16);
  });

  it("повреждение auth tag → ошибка расшифровки", () => {
    const enc = engine.encryptBuffer(Buffer.from("important data"));
    // Порча auth tag (байты 12–27)
    enc[14] = enc[14] ^ 0xff;
    expect(() => engine.decryptBuffer(enc)).toThrow(/Расшифровка не удалась/);
  });

  it("повреждение зашифрованных данных → ошибка расшифровки", () => {
    const enc = engine.encryptBuffer(Buffer.from("important data"));
    // Порча первого байта данных (после IV+AuthTag)
    enc[12 + 16] = enc[12 + 16] ^ 0xff;
    expect(() => engine.decryptBuffer(enc)).toThrow(/Расшифровка не удалась/);
  });

  it("слишком короткий буфер → явная ошибка с описанием", () => {
    const tooShort = Buffer.alloc(5);
    expect(() => engine.decryptBuffer(tooShort)).toThrow(/Файл повреждён/);
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
    await engine.deriveKey("stream-test-password");
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

  it("зашифрованный файл минимум на 28 байт больше оригинала (12 IV + 16 AuthTag)", async () => {
    const srcPath = path.join(tempDir, "small.txt");
    const encPath = path.join(tempDir, "small.txt.enc");
    const content = "tiny";
    fs.writeFileSync(srcPath, content);

    await engine.encryptStream(srcPath, encPath);

    const originalSize = fs.statSync(srcPath).size;
    const encSize = fs.statSync(encPath).size;
    expect(encSize).toBe(originalSize + 12 + 16);
  });
});

// ─────────────────────────────────────────────
// Тесты уничтожения ключа
// ─────────────────────────────────────────────

describe("CryptoEngine — destroy()", () => {
  it("после destroy() isUnlocked() возвращает false", async () => {
    const engine = new CryptoEngine();
    await engine.deriveKey("password");
    expect(engine.isUnlocked()).toBe(true);

    engine.destroy();
    expect(engine.isUnlocked()).toBe(false);
  });

  it("после destroy() encryptBuffer бросает ошибку", async () => {
    const engine = new CryptoEngine();
    await engine.deriveKey("password");
    engine.destroy();
    expect(() => engine.encryptBuffer(Buffer.from("x"))).toThrow(/Ключ не загружен/);
  });

  it("повторный вызов destroy() не бросает ошибку", async () => {
    const engine = new CryptoEngine();
    await engine.deriveKey("password");
    engine.destroy();
    expect(() => engine.destroy()).not.toThrow();
  });
});
