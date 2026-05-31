/**
 * Тесты миграции legacy → v2 (ФАЗА 4).
 *
 * Генерируем legacy-node и legacy-web буферы ТОЧНО по старым параметрам
 * (сверены с commit 0a66e2e), затем проверяем что мигратор их детектит,
 * расшифровывает trial-decrypt'ом, перешифровывает в валидный v2 и round-trip
 * совпадает. Плюс: идемпотентность, неверный пароль, verify-перед-заменой.
 */

import { describe, it, expect } from "@jest/globals";
import * as nodeCrypto from "crypto";
import { NodeCryptoEngine } from "../src/crypto-engine";
import { detectFormat, isV2 } from "../src/crypto/format";
import {
  legacyDecrypt,
} from "../src/crypto/legacy";
import {
  migrateBuffer,
  probeLegacyPassword,
} from "../src/crypto/migration";
import {
  LEGACY_SALT_DOMAIN,
  LEGACY_PBKDF2_ITERATIONS_NODE,
  LEGACY_PBKDF2_ITERATIONS_WEB,
} from "../src/crypto/constants";

const EMAIL = "Alice@Example.com";
const PASSWORD = "correct horse battery staple";

// ── Генераторы legacy-буферов по ТОЧНЫМ старым параметрам ──────────────────

/** Деривация старого ключа: PBKDF2(password, "shadow-vault:v1", iters, sha512, 32). */
function legacyKey(iters: number): Buffer {
  return nodeCrypto.pbkdf2Sync(
    PASSWORD,
    Buffer.from(LEGACY_SALT_DOMAIN, "utf8"),
    iters,
    32,
    "sha512"
  );
}

/** Старый crypto-engine.ts: [IV(12)][AuthTag(16)][ciphertext], 310000 итераций. */
function makeLegacyNode(plaintext: Buffer): Buffer {
  const key = legacyKey(LEGACY_PBKDF2_ITERATIONS_NODE);
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // tag ПЕРЕД ciphertext — ключевое отличие legacy-node
  return Buffer.concat([iv, tag, enc]);
}

/** Старый web-crypto-engine.ts: [IV(12)][ciphertext‖tag], 600000 итераций. */
function makeLegacyWeb(plaintext: Buffer): Buffer {
  const key = legacyKey(LEGACY_PBKDF2_ITERATIONS_WEB);
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // tag В КОНЦЕ (как отдаёт WebCrypto)
  return Buffer.concat([iv, enc, tag]);
}

async function v2Engine(): Promise<NodeCryptoEngine> {
  const e = new NodeCryptoEngine();
  await e.deriveKey(EMAIL, PASSWORD);
  return e;
}

// ─────────────────────────────────────────────────────────────────────────

describe("legacyDecrypt: trial-decrypt обоих вариантов", () => {
  it("расшифровывает legacy-node и распознаёт вариант", async () => {
    const plain = Buffer.from("Привет, legacy-node!\n# Заголовок", "utf8");
    const buf = makeLegacyNode(plain);
    const res = await legacyDecrypt(new Uint8Array(buf), PASSWORD);
    expect(res.variant).toBe("legacy-node");
    expect(Buffer.from(res.plaintext).equals(plain)).toBe(true);
  });

  it("расшифровывает legacy-web и распознаёт вариант", async () => {
    const plain = Buffer.from("web content тест", "utf8");
    const buf = makeLegacyWeb(plain);
    const res = await legacyDecrypt(new Uint8Array(buf), PASSWORD);
    expect(res.variant).toBe("legacy-web");
    expect(Buffer.from(res.plaintext).equals(plain)).toBe(true);
  });

  it("пустой буфер → пустой plaintext", async () => {
    const res = await legacyDecrypt(new Uint8Array(0), PASSWORD);
    expect(res.plaintext.length).toBe(0);
  });

  it("неверный пароль → ошибка (оба варианта падают)", async () => {
    const buf = makeLegacyNode(Buffer.from("secret"));
    await expect(
      legacyDecrypt(new Uint8Array(buf), "wrong-password")
    ).rejects.toThrow();
  });
});

describe("migrateBuffer: legacy → v2 с round-trip verify", () => {
  it("legacy-node → валидный v2, plaintext совпадает", async () => {
    const plain = Buffer.from("файл из старого хранилища", "utf8");
    const legacy = makeLegacyNode(plain);
    const engine = await v2Engine();

    const res = await migrateBuffer(new Uint8Array(legacy), PASSWORD, engine);
    expect(res.status).toBe("migrated");
    if (res.status !== "migrated") throw new Error("unreachable");

    expect(res.variant).toBe("legacy-node");
    expect(isV2(res.v2)).toBe(true);
    expect(detectFormat(res.v2)).toBe("v2");
    // v2 расшифровывается тем же движком в исходный plaintext
    const back = engine.decryptBuffer(Buffer.from(res.v2));
    expect(back.equals(plain)).toBe(true);
  });

  it("legacy-web → валидный v2, plaintext совпадает", async () => {
    const plain = Buffer.from("web → v2 миграция", "utf8");
    const legacy = makeLegacyWeb(plain);
    const engine = await v2Engine();

    const res = await migrateBuffer(new Uint8Array(legacy), PASSWORD, engine);
    expect(res.status).toBe("migrated");
    if (res.status !== "migrated") throw new Error("unreachable");
    expect(res.variant).toBe("legacy-web");
    const back = engine.decryptBuffer(Buffer.from(res.v2));
    expect(back.equals(plain)).toBe(true);
  });

  it("идемпотентность: повторный прогон над v2 → skipped-v2", async () => {
    const plain = Buffer.from("идемпотентность", "utf8");
    const legacy = makeLegacyNode(plain);
    const engine = await v2Engine();

    const first = await migrateBuffer(new Uint8Array(legacy), PASSWORD, engine);
    if (first.status !== "migrated") throw new Error("unreachable");

    // Повторный прогон над уже-v2 буфером не должен ничего портить.
    const second = await migrateBuffer(first.v2, PASSWORD, engine);
    expect(second.status).toBe("skipped-v2");
  });

  it("неверный пароль → ошибка, ничего не возвращается", async () => {
    const legacy = makeLegacyNode(Buffer.from("data"));
    const engine = await v2Engine();
    await expect(
      migrateBuffer(new Uint8Array(legacy), "wrong", engine)
    ).rejects.toThrow();
  });

  it("verify-перед-заменой: подделанный движок ловится round-trip'ом", async () => {
    const plain = Buffer.from("честные данные", "utf8");
    const legacy = makeLegacyNode(plain);
    const honest = await v2Engine();

    // Движок-«подделка»: шифрует корректно, но при decryptBuffer возвращает мусор.
    const tampered = {
      encryptBuffer: (d: Uint8Array | ArrayBuffer | Buffer) =>
        honest.encryptBuffer(Buffer.from(d as Uint8Array)),
      decryptBuffer: () => Buffer.from("ДРУГОЙ plaintext"),
    };

    await expect(
      migrateBuffer(new Uint8Array(legacy), PASSWORD, tampered)
    ).rejects.toThrow(/round-trip verify/);
  });
});

describe("probeLegacyPassword (три различимых исхода)", () => {
  it("legacy + верный пароль → LEGACY_OK с вариантом", async () => {
    const buf = makeLegacyWeb(Buffer.from("проба"));
    const res = await probeLegacyPassword(new Uint8Array(buf), PASSWORD);
    expect(res.status).toBe("LEGACY_OK");
    if (res.status !== "LEGACY_OK") throw new Error("unreachable");
    expect(res.variant).toBe("legacy-web");
  });

  it("legacy + неверный пароль → LEGACY_WRONG_PASSWORD", async () => {
    const buf = makeLegacyNode(Buffer.from("проба"));
    const res = await probeLegacyPassword(new Uint8Array(buf), "nope");
    expect(res.status).toBe("LEGACY_WRONG_PASSWORD");
  });

  it("v2-образец → NOT_LEGACY (уже мигрировано, миграция не нужна)", async () => {
    const engine = await v2Engine();
    const v2 = engine.encryptBuffer(Buffer.from("x"));
    const res = await probeLegacyPassword(new Uint8Array(v2), PASSWORD);
    expect(res.status).toBe("NOT_LEGACY");
  });

  it("пустой (0 байт) образец → NOT_LEGACY (не legacy)", async () => {
    const res = await probeLegacyPassword(new Uint8Array(0), PASSWORD);
    expect(res.status).toBe("NOT_LEGACY");
  });

  it("v2-образец с НЕВЕРНЫМ паролем тоже NOT_LEGACY (не путаем с wrong-password)", async () => {
    const engine = await v2Engine();
    const v2 = engine.encryptBuffer(Buffer.from("y"));
    const res = await probeLegacyPassword(new Uint8Array(v2), "totally-wrong");
    expect(res.status).toBe("NOT_LEGACY");
  });
});
