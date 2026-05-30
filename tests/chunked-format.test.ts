/**
 * Тесты чанкового под-формата v2-chunked (0x03) — ФАЗА 5, задача 2.
 *
 * Покрывают:
 *   - detectFormat различает цельный v2 (0x02) и чанковый (0x03);
 *   - desktop encryptStream больших файлов пишет чанково и round-trip корректен;
 *   - кросс-читаемость: чанковый контейнер, записанный NodeCryptoEngine,
 *     расшифровывается WebCryptoEngine (mobile-путь) посегментно через subtle;
 *   - decryptStream читает чанковый файл потоково и даёт исходные байты;
 *   - повреждение сегмента ловится (Auth Tag mismatch).
 */

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { NodeCryptoEngine } from "../src/crypto-engine";
import { WebCryptoEngine } from "../src/web-crypto-engine";
import { detectFormat, isChunked } from "../src/crypto/format";
import { CHUNK_BLOCK_SIZE, CHUNKED_THRESHOLD } from "../src/crypto/constants";

const TEST_EMAIL = "chunk@example.com";
const TEST_PASS = "chunked-format-password";

function makeTempDir(): { dir: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shadowvault-chunk-"));
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

/** Псевдослучайные, но детерминированные байты заданной длины. */
function pseudoRandom(len: number): Buffer {
  const out = Buffer.alloc(len);
  let x = 0x12345678;
  for (let i = 0; i < len; i++) {
    x = (x * 1664525 + 1013904223) >>> 0;
    out[i] = x & 0xff;
  }
  return out;
}

describe("v2-chunked: detectFormat различает 0x02 и 0x03", () => {
  let node: NodeCryptoEngine;
  let tmp: { dir: string; cleanup: () => void };

  beforeEach(async () => {
    node = new NodeCryptoEngine();
    await node.deriveKey(TEST_EMAIL, TEST_PASS);
    tmp = makeTempDir();
  });
  afterEach(() => {
    node.destroy();
    tmp.cleanup();
  });

  it("цельный encryptBuffer → v2 (0x02)", () => {
    const enc = node.encryptBuffer(Buffer.from("hello"));
    expect(detectFormat(enc)).toBe("v2");
    expect(isChunked(enc)).toBe(false);
  });

  it("большой файл через encryptStream → v2-chunked (0x03)", async () => {
    const src = path.join(tmp.dir, "big.bin");
    const enc = path.join(tmp.dir, "big.bin.enc");
    // Чуть больше порога — гарантированно чанковый и многосегментный.
    const data = pseudoRandom(CHUNKED_THRESHOLD + CHUNK_BLOCK_SIZE + 12345);
    fs.writeFileSync(src, data);

    await node.encryptStream(src, enc);
    const head = fs.readFileSync(enc).subarray(0, 9);
    expect(detectFormat(head)).toBe("v2-chunked");
  });

  it("маленький файл через encryptStream → остаётся цельным v2 (0x02)", async () => {
    const src = path.join(tmp.dir, "small.md");
    const enc = path.join(tmp.dir, "small.md.enc");
    fs.writeFileSync(src, "обычная заметка");

    await node.encryptStream(src, enc);
    const head = fs.readFileSync(enc).subarray(0, 9);
    expect(detectFormat(head)).toBe("v2");
  });
});

describe("v2-chunked: round-trip больших данных (desktop stream)", () => {
  let node: NodeCryptoEngine;
  let tmp: { dir: string; cleanup: () => void };

  beforeEach(async () => {
    node = new NodeCryptoEngine();
    await node.deriveKey(TEST_EMAIL, TEST_PASS);
    tmp = makeTempDir();
  });
  afterEach(() => {
    node.destroy();
    tmp.cleanup();
  });

  it("encryptStream → decryptStream даёт исходные байты (многосегментный)", async () => {
    const src = path.join(tmp.dir, "v.bin");
    const enc = path.join(tmp.dir, "v.bin.enc");
    const dec = path.join(tmp.dir, "v.out");
    const data = pseudoRandom(CHUNK_BLOCK_SIZE * 3 + 777);
    fs.writeFileSync(src, data);

    await node.encryptStream(src, enc);
    expect(detectFormat(fs.readFileSync(enc).subarray(0, 9))).toBe("v2-chunked");

    await node.decryptStream(enc, dec);
    expect(fs.readFileSync(dec).equals(data)).toBe(true);
  });

  it("ровно blockSize байт (граница): один сегмент, корректный round-trip", async () => {
    const src = path.join(tmp.dir, "exact.bin");
    const enc = path.join(tmp.dir, "exact.bin.enc");
    const dec = path.join(tmp.dir, "exact.out");
    // Размер >= порога, но кратен блоку — последний сегмент ровно blockSize.
    const data = pseudoRandom(CHUNKED_THRESHOLD);
    fs.writeFileSync(src, data);

    await node.encryptStream(src, enc);
    await node.decryptStream(enc, dec);
    expect(fs.readFileSync(dec).equals(data)).toBe(true);
  });

  it("decryptBuffer (в памяти) тоже умеет чанковый контейнер", async () => {
    const src = path.join(tmp.dir, "m.bin");
    const enc = path.join(tmp.dir, "m.bin.enc");
    const data = pseudoRandom(CHUNK_BLOCK_SIZE + 5000);
    fs.writeFileSync(src, data);

    await node.encryptStream(src, enc);
    const container = fs.readFileSync(enc);
    const plain = node.decryptBuffer(container);
    expect(plain.equals(data)).toBe(true);
  });
});

describe("v2-chunked: кросс-читаемость Node → Web (mobile)", () => {
  let node: NodeCryptoEngine;
  let web: WebCryptoEngine;
  let tmp: { dir: string; cleanup: () => void };

  beforeEach(async () => {
    node = new NodeCryptoEngine();
    web = new WebCryptoEngine();
    await node.deriveKey(TEST_EMAIL, TEST_PASS);
    await web.deriveKey(TEST_EMAIL, TEST_PASS);
    tmp = makeTempDir();
  });
  afterEach(() => {
    node.destroy();
    web.destroy();
    tmp.cleanup();
  });

  it("чанковый контейнер от desktop расшифровывается WebCrypto посегментно", async () => {
    const src = path.join(tmp.dir, "cross.bin");
    const enc = path.join(tmp.dir, "cross.bin.enc");
    const data = pseudoRandom(CHUNK_BLOCK_SIZE * 2 + 4096);
    fs.writeFileSync(src, data);

    await node.encryptStream(src, enc);
    const container = fs.readFileSync(enc);
    expect(detectFormat(container)).toBe("v2-chunked");

    const plain = await web.decryptBuffer(container);
    expect(Buffer.from(new Uint8Array(plain)).equals(data)).toBe(true);
  });

  it("маленький чанковый файл (один сегмент) тоже читается WebCrypto", async () => {
    const src = path.join(tmp.dir, "one.bin");
    const enc = path.join(tmp.dir, "one.bin.enc");
    const data = pseudoRandom(CHUNKED_THRESHOLD + 1);
    fs.writeFileSync(src, data);

    await node.encryptStream(src, enc);
    const plain = await web.decryptBuffer(fs.readFileSync(enc));
    expect(Buffer.from(new Uint8Array(plain)).equals(data)).toBe(true);
  });
});

describe("v2-chunked: целостность", () => {
  let node: NodeCryptoEngine;
  let tmp: { dir: string; cleanup: () => void };

  beforeEach(async () => {
    node = new NodeCryptoEngine();
    await node.deriveKey(TEST_EMAIL, TEST_PASS);
    tmp = makeTempDir();
  });
  afterEach(() => {
    node.destroy();
    tmp.cleanup();
  });

  it("порча байта в сегменте → ошибка расшифровки", async () => {
    const src = path.join(tmp.dir, "bad.bin");
    const enc = path.join(tmp.dir, "bad.bin.enc");
    const dec = path.join(tmp.dir, "bad.out");
    const data = pseudoRandom(CHUNK_BLOCK_SIZE + 100);
    fs.writeFileSync(src, data);

    await node.encryptStream(src, enc);
    const buf = fs.readFileSync(enc);
    // Портим байт внутри первого сегмента (после заголовка контейнера и длины).
    buf[20] ^= 0xff;
    fs.writeFileSync(enc, buf);

    await expect(node.decryptStream(enc, dec)).rejects.toThrow();
  });
});
