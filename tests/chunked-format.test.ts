/**
 * Тесты чанкового под-формата v2-chunked — ФАЗА 5, задача 2.
 *
 * Покрывают:
 *   - detectFormat различает цельный v2 (0x02) и чанковый (0x03/0x04);
 *   - desktop encryptStream больших файлов пишет чанково (ТОЛЬКО 0x04)
 *     и round-trip корректен;
 *   - кросс-читаемость: чанковый контейнер, записанный NodeCryptoEngine,
 *     расшифровывается WebCryptoEngine (mobile-путь) посегментно через subtle;
 *   - decryptStream читает чанковый файл потоково и даёт исходные байты;
 *   - повреждение сегмента ловится (Auth Tag mismatch);
 *   - криптографическая связка сегментов 0x04 (AAD = заголовок ‖ индекс):
 *     перестановка/удаление/дублирование/усечение/подстановка из другого
 *     файла → ошибка целостности, а не «успешная» расшифровка;
 *   - plaintextSizeFromContainer строг на усечённом 0x04;
 *   - обратная совместимость: legacy-контейнер 0x03 (фикстура, собранная
 *     байт-в-байт как старый писатель) читается обоими движками.
 */

import {
  describe,
  it,
  expect,
  beforeEach,
  beforeAll,
  afterEach,
  afterAll,
} from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as nodeCrypto from "crypto";
import { NodeCryptoEngine } from "../src/crypto-engine";
import { WebCryptoEngine } from "../src/web-crypto-engine";
import {
  detectFormat,
  isChunked,
  chunkedVersion,
  plaintextSizeFromContainer,
  writeChunkedHeader,
  writeSegment,
  CHUNKED2_HEADER_LENGTH,
} from "../src/crypto/format";
import {
  CHUNK_BLOCK_SIZE,
  CHUNKED_THRESHOLD,
  FORMAT_VERSION_CHUNKED,
  FORMAT_VERSION_CHUNKED2,
  IV_LENGTH,
  MAGIC_LENGTH,
} from "../src/crypto/constants";
import { deriveMasterKey } from "../src/crypto/key-derivation";

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

  it("большой файл через encryptStream → v2-chunked НОВОЙ версии (0x04)", async () => {
    const src = path.join(tmp.dir, "big.bin");
    const enc = path.join(tmp.dir, "big.bin.enc");
    // Чуть больше порога — гарантированно чанковый и многосегментный.
    const data = pseudoRandom(CHUNKED_THRESHOLD + CHUNK_BLOCK_SIZE + 12345);
    fs.writeFileSync(src, data);

    await node.encryptStream(src, enc);
    const head = fs.readFileSync(enc).subarray(0, CHUNKED2_HEADER_LENGTH);
    expect(detectFormat(head)).toBe("v2-chunked");
    // Запись — ТОЛЬКО новая версия 0x04 со связкой сегментов.
    expect(head[MAGIC_LENGTH]).toBe(FORMAT_VERSION_CHUNKED2);
    expect(chunkedVersion(head)).toBe(4);
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
    buf[CHUNKED2_HEADER_LENGTH + 4 + IV_LENGTH + 3] ^= 0xff;
    fs.writeFileSync(enc, buf);

    await expect(node.decryptStream(enc, dec)).rejects.toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Хелперы для тестов связки сегментов
// ─────────────────────────────────────────────────────────────────────────────

/** Разбирает чанковый контейнер на заголовок и сырые сегменты ([len][IV][ct‖tag]). */
function splitContainer(buf: Buffer, headerLen: number): { header: Buffer; segs: Buffer[] } {
  const header = Buffer.from(buf.subarray(0, headerLen));
  const segs: Buffer[] = [];
  let off = headerLen;
  while (off < buf.length) {
    const segLen = buf.readUInt32LE(off);
    segs.push(Buffer.from(buf.subarray(off, off + 4 + segLen)));
    off += 4 + segLen;
  }
  return { header, segs };
}

/** Ожидает, что промис отклонится (устойчиво к DOMException из WebCrypto). */
async function expectAsyncThrow(p: Promise<unknown>): Promise<void> {
  let threw = false;
  try {
    await p;
  } catch {
    threw = true;
  }
  expect(threw).toBe(true);
}

describe("v2-chunked 0x04: криптографическая связка сегментов", () => {
  let node: NodeCryptoEngine;
  let web: WebCryptoEngine;
  let tmp: { dir: string; cleanup: () => void };
  let data: Buffer;
  let containerA: Buffer; // 3 сегмента
  let containerB: Buffer; // другой файл, тот же ключ (для подстановки)
  let mutCounter = 0;

  beforeAll(async () => {
    node = new NodeCryptoEngine();
    web = new WebCryptoEngine();
    await node.deriveKey(TEST_EMAIL, TEST_PASS);
    await web.deriveKey(TEST_EMAIL, TEST_PASS);
    tmp = makeTempDir();

    data = pseudoRandom(CHUNK_BLOCK_SIZE * 2 + 4096); // ровно 3 сегмента
    const srcA = path.join(tmp.dir, "a.bin");
    const encA = path.join(tmp.dir, "a.bin.enc");
    fs.writeFileSync(srcA, data);
    await node.encryptStream(srcA, encA);
    containerA = fs.readFileSync(encA);

    const dataB = pseudoRandom(CHUNK_BLOCK_SIZE * 2 + 4096).reverse();
    const srcB = path.join(tmp.dir, "b.bin");
    const encB = path.join(tmp.dir, "b.bin.enc");
    fs.writeFileSync(srcB, Buffer.from(dataB));
    await node.encryptStream(srcB, encB);
    containerB = fs.readFileSync(encB);
  }, 30000);

  afterAll(() => {
    node.destroy();
    web.destroy();
    tmp.cleanup();
  });

  /** Собирает контейнер из заголовка и сегментов. */
  const assemble = (header: Buffer, segs: Buffer[]): Buffer =>
    Buffer.concat([header, ...segs]);

  /**
   * Проверяет, что испорченный контейнер отвергают ВСЕ три пути чтения:
   * Node decryptBuffer, Node decryptStream (потоково) и WebCrypto (mobile).
   */
  const expectRejectedEverywhere = async (mut: Buffer): Promise<void> => {
    expect(() => node.decryptBuffer(mut)).toThrow();
    await expectAsyncThrow(web.decryptBuffer(mut));
    const encPath = path.join(tmp.dir, `mut-${mutCounter}.enc`);
    const outPath = path.join(tmp.dir, `mut-${mutCounter}.out`);
    mutCounter++;
    fs.writeFileSync(encPath, mut);
    await expectAsyncThrow(node.decryptStream(encPath, outPath));
  };

  it("sanity: нетронутый контейнер (3 сегмента) читается Node и Web", async () => {
    const { segs } = splitContainer(containerA, CHUNKED2_HEADER_LENGTH);
    expect(segs.length).toBe(3);
    expect(node.decryptBuffer(containerA).equals(data)).toBe(true);
    const plain = await web.decryptBuffer(containerA);
    expect(Buffer.from(new Uint8Array(plain)).equals(data)).toBe(true);
  });

  it("перестановка двух сегментов → ошибка целостности", async () => {
    const { header, segs } = splitContainer(containerA, CHUNKED2_HEADER_LENGTH);
    // Сегменты 0 и 1 оба ровно blockSize — длины совпадают, ловит только AAD.
    await expectRejectedEverywhere(assemble(header, [segs[1], segs[0], segs[2]]));
  });

  it("удаление сегмента → ошибка целостности", async () => {
    const { header, segs } = splitContainer(containerA, CHUNKED2_HEADER_LENGTH);
    await expectRejectedEverywhere(assemble(header, [segs[0], segs[2]]));
  });

  it("дублирование сегмента (замена соседним, длина та же) → ошибка", async () => {
    const { header, segs } = splitContainer(containerA, CHUNKED2_HEADER_LENGTH);
    await expectRejectedEverywhere(assemble(header, [segs[0], segs[0], segs[2]]));
  });

  it("дублирование сегмента добавлением в конец → ошибка", async () => {
    const { header, segs } = splitContainer(containerA, CHUNKED2_HEADER_LENGTH);
    await expectRejectedEverywhere(assemble(header, [...segs, segs[2]]));
  });

  it("обрезка до одного заголовка → ошибка, а не 0 байт plaintext", async () => {
    const { header } = splitContainer(containerA, CHUNKED2_HEADER_LENGTH);
    await expectRejectedEverywhere(assemble(header, []));
  });

  it("обрезка до N первых сегментов → ошибка, а не частичные данные", async () => {
    const { header, segs } = splitContainer(containerA, CHUNKED2_HEADER_LENGTH);
    await expectRejectedEverywhere(assemble(header, [segs[0]]));
    await expectRejectedEverywhere(assemble(header, [segs[0], segs[1]]));
  });

  it("подстановка сегмента из другого файла с тем же ключом → ошибка", async () => {
    const a = splitContainer(containerA, CHUNKED2_HEADER_LENGTH);
    const b = splitContainer(containerB, CHUNKED2_HEADER_LENGTH);
    // Тот же индекс (1), тот же ключ, та же длина — ловится fileId в AAD.
    await expectRejectedEverywhere(assemble(a.header, [a.segs[0], b.segs[1], a.segs[2]]));
  });

  it("порча blockSize в заголовке → ошибка (заголовок аутентифицирован)", async () => {
    const mut = Buffer.from(containerA);
    mut[MAGIC_LENGTH + 1] ^= 0xff; // младший байт blockSize
    await expectRejectedEverywhere(mut);
  });

  it("порча fileId в заголовке → ошибка", async () => {
    const mut = Buffer.from(containerA);
    mut[CHUNKED2_HEADER_LENGTH - 1] ^= 0xff; // последний байт fileId
    await expectRejectedEverywhere(mut);
  });
});

describe("v2-chunked 0x04: plaintextSizeFromContainer строг к усечению", () => {
  let node: NodeCryptoEngine;
  let tmp: { dir: string; cleanup: () => void };
  let data: Buffer;
  let container: Buffer;

  beforeAll(async () => {
    node = new NodeCryptoEngine();
    await node.deriveKey(TEST_EMAIL, TEST_PASS);
    tmp = makeTempDir();
    data = pseudoRandom(CHUNK_BLOCK_SIZE * 2 + 999);
    const src = path.join(tmp.dir, "s.bin");
    const enc = path.join(tmp.dir, "s.bin.enc");
    fs.writeFileSync(src, data);
    await node.encryptStream(src, enc);
    container = fs.readFileSync(enc);
  }, 30000);

  afterAll(() => {
    node.destroy();
    tmp.cleanup();
  });

  it("на целом контейнере возвращает точный размер plaintext", () => {
    expect(plaintextSizeFromContainer(container)).toBe(data.length);
  });

  it("обрезка до заголовка → исключение (не 0)", () => {
    const { header } = splitContainer(container, CHUNKED2_HEADER_LENGTH);
    expect(() => plaintextSizeFromContainer(header)).toThrow();
  });

  it("обрезка до N сегментов → исключение (не частичная сумма)", () => {
    const { header, segs } = splitContainer(container, CHUNKED2_HEADER_LENGTH);
    const truncated = Buffer.concat([header, segs[0]]);
    expect(() => plaintextSizeFromContainer(truncated)).toThrow();
  });

  it("обрыв посреди сегмента → исключение", () => {
    const truncated = container.subarray(0, container.length - 5);
    expect(() => plaintextSizeFromContainer(truncated)).toThrow();
  });
});

describe("v2-chunked 0x03 (legacy): обратная совместимость чтения", () => {
  // Фикстура собирается БАЙТ-В-БАЙТ как старый писатель 0x03 (до связки
  // сегментов): заголовок MAGIC+0x03+blockSize и независимые AES-GCM
  // сегменты БЕЗ AAD (writeChunkedHeader/writeSegment сохранены для этого).
  const LEGACY_BLOCK = 1024;

  let node: NodeCryptoEngine;
  let web: WebCryptoEngine;
  let tmp: { dir: string; cleanup: () => void };
  let data: Buffer;
  let legacyContainer: Buffer;

  beforeAll(async () => {
    node = new NodeCryptoEngine();
    web = new WebCryptoEngine();
    await node.deriveKey(TEST_EMAIL, TEST_PASS);
    await web.deriveKey(TEST_EMAIL, TEST_PASS);
    tmp = makeTempDir();

    const rawKey = await deriveMasterKey(TEST_EMAIL, TEST_PASS);
    data = pseudoRandom(LEGACY_BLOCK * 2 + 512); // 3 сегмента: 1024+1024+512

    const parts: Uint8Array[] = [writeChunkedHeader(LEGACY_BLOCK)];
    for (let off = 0; off < data.length; off += LEGACY_BLOCK) {
      const block = data.subarray(off, Math.min(off + LEGACY_BLOCK, data.length));
      const iv = nodeCrypto.randomBytes(IV_LENGTH);
      const cipher = nodeCrypto.createCipheriv("aes-256-gcm", Buffer.from(rawKey), iv);
      const ct = Buffer.concat([cipher.update(block), cipher.final()]);
      const tag = cipher.getAuthTag();
      parts.push(writeSegment(iv, Buffer.concat([ct, tag])));
    }
    legacyContainer = Buffer.concat(parts);
  }, 30000);

  afterAll(() => {
    node.destroy();
    web.destroy();
    tmp.cleanup();
  });

  it("детектируется как v2-chunked версии 3", () => {
    expect(detectFormat(legacyContainer)).toBe("v2-chunked");
    expect(isChunked(legacyContainer)).toBe(true);
    expect(legacyContainer[MAGIC_LENGTH]).toBe(FORMAT_VERSION_CHUNKED);
    expect(chunkedVersion(legacyContainer)).toBe(3);
  });

  it("NodeCryptoEngine.decryptBuffer читает legacy 0x03", () => {
    expect(node.decryptBuffer(legacyContainer).equals(data)).toBe(true);
  });

  it("NodeCryptoEngine.decryptStream читает legacy 0x03 потоково", async () => {
    const enc = path.join(tmp.dir, "legacy.enc");
    const out = path.join(tmp.dir, "legacy.out");
    fs.writeFileSync(enc, legacyContainer);
    await node.decryptStream(enc, out);
    expect(fs.readFileSync(out).equals(data)).toBe(true);
  });

  it("WebCryptoEngine.decryptBuffer читает legacy 0x03 (mobile)", async () => {
    const plain = await web.decryptBuffer(legacyContainer);
    expect(Buffer.from(new Uint8Array(plain)).equals(data)).toBe(true);
  });

  it("plaintextSizeFromContainer на целом 0x03 — точный размер", () => {
    expect(plaintextSizeFromContainer(legacyContainer)).toBe(data.length);
  });

  it("plaintextSizeFromContainer на усечённом 0x03 — частичная сумма (историческое поведение, без исключения)", () => {
    const { header, segs } = splitContainer(legacyContainer, 9);
    const truncated = Buffer.concat([header, segs[0]]);
    expect(plaintextSizeFromContainer(truncated)).toBe(LEGACY_BLOCK);
  });
});
