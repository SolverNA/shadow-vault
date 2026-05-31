/**
 * Тесты мобильного (виртуального) VFS-слоя: VirtualShadowManager поверх
 * абстракции PlatformAdapter с движком WebCryptoEngine.
 *
 * Что проверяем (ФАЗА 2):
 *   - mobile-путь ПИШЕТ .enc в формате v2 (MAGIC "SVLT" + version 0x02);
 *   - то, что записано mobile-путём, корректно ЧИТАЕТСЯ обратно (round-trip);
 *   - read/write/exists/remove/rename/stat/list работают через единый
 *     PlatformAdapter без node:fs (in-memory реализация → mobile-safe).
 *
 * Фейковый InMemoryAdapter реализует тот же интерфейс PlatformAdapter, что и
 * MobileAdapter (Obsidian Vault) — это доказывает, что слой не зависит от Node.
 */

import { describe, it, expect, beforeEach } from "@jest/globals";
import { WebCryptoEngine } from "../src/web-crypto-engine";
import { VirtualShadowManager } from "../src/virtual-shadow-manager";
import { PlatformAdapter } from "../src/platform-adapter";
import { isV2 } from "../src/crypto/format";

const STUB_EMAIL = "test@shadow-vault.local";

/** In-memory реализация PlatformAdapter — без node:fs (как mobile Vault API). */
class InMemoryAdapter implements PlatformAdapter {
  files = new Map<string, ArrayBuffer>();

  async readBinary(path: string): Promise<ArrayBuffer> {
    const v = this.files.get(path);
    if (!v) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    return v;
  }
  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    this.files.set(path, data);
  }
  async exists(path: string): Promise<boolean> {
    return this.files.has(path);
  }
  async remove(path: string): Promise<void> {
    this.files.delete(path);
  }
  async list(path: string): Promise<{ files: string[]; folders: string[] }> {
    const prefix = path ? path + "/" : "";
    const files: string[] = [];
    const folders = new Set<string>();
    for (const key of this.files.keys()) {
      if (!key.startsWith(prefix)) continue;
      const rest = key.slice(prefix.length);
      const slash = rest.indexOf("/");
      if (slash === -1) {
        files.push(key);
      } else {
        folders.add(prefix + rest.slice(0, slash));
      }
    }
    return { files, folders: [...folders] };
  }
  async mkdir(): Promise<void> {
    /* папки в in-memory не нужны */
  }
  async stat(path: string): Promise<{ size: number; mtime: number } | null> {
    const v = this.files.get(path);
    if (!v) return null;
    return { size: v.byteLength, mtime: 1000 };
  }
}

function bytes(s: string): ArrayBuffer {
  return new TextEncoder().encode(s).buffer;
}
function text(b: ArrayBuffer): string {
  return new TextDecoder().decode(b);
}

let engine: WebCryptoEngine;
let adapter: InMemoryAdapter;
let vsm: VirtualShadowManager;

beforeEach(async () => {
  engine = new WebCryptoEngine();
  await engine.deriveKey(STUB_EMAIL, "correct horse battery staple");
  adapter = new InMemoryAdapter();
  vsm = new VirtualShadowManager(engine, adapter);
});

describe("VirtualShadowManager (mobile write-through)", () => {
  it("write пишет .enc в формате v2", async () => {
    await vsm.write("note.md", bytes("hello mobile"));

    const enc = adapter.files.get("note.md.enc");
    expect(enc).toBeTruthy();
    expect(isV2(new Uint8Array(enc!))).toBe(true);
    // зашифровано: не равно plaintext
    expect(text(enc!)).not.toContain("hello mobile");
  });

  it("round-trip: что записано, то и читается (даже без кэша)", async () => {
    await vsm.write("a/b/note.md", bytes("secret payload"));

    // Новый VSM без прогретого кэша — читает строго из .enc на адаптере
    const fresh = new VirtualShadowManager(engine, adapter);
    const out = await fresh.read("a/b/note.md");
    expect(text(out)).toBe("secret payload");
  });

  it(".enc расшифровывается обратно тем же engine (формат v2 совместим)", async () => {
    await vsm.write("x.md", bytes("v2 roundtrip"));
    const enc = adapter.files.get("x.md.enc")!;
    const dec = await engine.decryptBuffer(enc);
    expect(text(dec)).toBe("v2 roundtrip");
  });

  it("exists учитывает и кэш, и .enc на адаптере", async () => {
    expect(await vsm.exists("none.md")).toBe(false);
    await vsm.write("present.md", bytes("data"));
    expect(await vsm.exists("present.md")).toBe(true);

    // даже после сброса кэша exists видит .enc
    const fresh = new VirtualShadowManager(engine, adapter);
    expect(await fresh.exists("present.md")).toBe(true);
  });

  it("remove удаляет .enc и из кэша", async () => {
    await vsm.write("del.md", bytes("bye"));
    await vsm.remove("del.md");
    expect(adapter.files.has("del.md.enc")).toBe(false);
    expect(await vsm.exists("del.md")).toBe(false);
  });

  it("rename переносит .enc и сохраняет содержимое", async () => {
    await vsm.write("old.md", bytes("movable"));
    await vsm.rename("old.md", "new.md");

    expect(adapter.files.has("old.md.enc")).toBe(false);
    expect(adapter.files.has("new.md.enc")).toBe(true);

    const fresh = new VirtualShadowManager(engine, adapter);
    expect(text(await fresh.read("new.md"))).toBe("movable");
  });

  it("list убирает суффикс .enc из имён файлов", async () => {
    await vsm.write("n1.md", bytes("1"));
    await vsm.write("n2.md", bytes("2"));
    const res = await vsm.list("");
    expect(res.files.sort()).toEqual(["n1.md", "n2.md"]);
  });

  it("stat возвращает размер plaintext (а не .enc) — из кэша", async () => {
    const data = bytes("size me"); // 7 байт
    await vsm.write("s.md", data);
    const st = await vsm.stat("s.md");
    expect(st).not.toBeNull();
    // Размер = plaintext (7), а не .enc (33 overhead + 7).
    expect(st!.size).toBe(data.byteLength);
    expect(st!.size).not.toBe(adapter.files.get("s.md.enc")!.byteLength);
  });

  it("stat возвращает размер plaintext при пустом кэше (по содержимому .enc)", async () => {
    const data = bytes("hello world"); // 11 байт
    await vsm.write("s2.md", data);
    // Свежий менеджер — кэша нет, размер считается по .enc без расшифровки.
    const fresh = new VirtualShadowManager(engine, adapter);
    const st = await fresh.stat("s2.md");
    expect(st).not.toBeNull();
    expect(st!.size).toBe(data.byteLength);
  });

  // ── H5: защита кэша от мутации по ссылке ───────────────────────────────
  it("мутация буфера, возвращённого read, НЕ портит кэш/последующие чтения", async () => {
    await vsm.write("m.md", bytes("original"));
    const first = new Uint8Array(await vsm.read("m.md"));
    // Портим возвращённый буфер
    first.fill(0);
    // Повторное чтение должно вернуть исходные данные
    const second = await vsm.read("m.md");
    expect(text(second)).toBe("original");
  });

  it("мутация буфера, переданного во write, НЕ портит кэш", async () => {
    const data = new TextEncoder().encode("payload");
    await vsm.write("w.md", data.buffer);
    // Мутируем исходный буфер после записи
    data.fill(0);
    const out = await vsm.read("w.md");
    expect(text(out)).toBe("payload");
  });

  // ── C2/H7: единый контракт пустых файлов ───────────────────────────────
  it("пустой plaintext → валидный v2-контейнер (не 0 байт)", async () => {
    await vsm.write("empty.md", new ArrayBuffer(0));
    const enc = adapter.files.get("empty.md.enc")!;
    expect(enc.byteLength).toBeGreaterThan(0);
    expect(isV2(new Uint8Array(enc))).toBe(true);
    // round-trip пустого
    const fresh = new VirtualShadowManager(engine, adapter);
    expect((await fresh.read("empty.md")).byteLength).toBe(0);
  });

  it("legacy 0-байтный .enc читается как пустой plaintext (без ошибки)", async () => {
    // Эмулируем legacy-артефакт: 0-байтный .enc на адаптере
    adapter.files.set("legacy.md.enc", new ArrayBuffer(0));
    const fresh = new VirtualShadowManager(engine, adapter);
    const out = await fresh.read("legacy.md");
    expect(out.byteLength).toBe(0);
    // stat тоже не падает и даёт 0
    const st = await fresh.stat("legacy.md");
    expect(st!.size).toBe(0);
  });

  it("reEncryptAll конвертит legacy 0-байтный .enc в валидный v2", async () => {
    adapter.files.set("z.md.enc", new ArrayBuffer(0));
    const newEngine = new WebCryptoEngine();
    await newEngine.deriveKey(STUB_EMAIL, "new password here");
    await vsm.reEncryptAll(".obsidian", newEngine);
    const enc = adapter.files.get("z.md.enc")!;
    expect(enc.byteLength).toBeGreaterThan(0);
    expect(isV2(new Uint8Array(enc))).toBe(true);
    expect((await newEngine.decryptBuffer(enc)).byteLength).toBe(0);
  });
});

describe("VirtualShadowManager.reEncryptAll (mobile смена ключа)", () => {
  it("пере-шифровывает все .enc новым ключом и читает их новым ключом", async () => {
    await vsm.write("a.md", bytes("payload A"));
    await vsm.write("dir/b.md", bytes("payload B"));

    // Новый ключ — другой email (новая соль), пароль не меняется.
    const newEngine = new WebCryptoEngine();
    await newEngine.deriveKey("new@shadow-vault.local", "correct horse battery staple");

    const progress: Array<[number, number]> = [];
    await vsm.reEncryptAll("", newEngine, (d, t) => progress.push([d, t]));

    // Старым ключом .enc больше не читается
    const oldReader = new VirtualShadowManager(engine, adapter);
    await expect(oldReader.read("a.md")).rejects.toBeTruthy();

    // Новым ключом — читается корректно
    const newReader = new VirtualShadowManager(newEngine, adapter);
    expect(text(await newReader.read("a.md"))).toBe("payload A");
    expect(text(await newReader.read("dir/b.md"))).toBe("payload B");

    expect(progress.length).toBeGreaterThan(0);
  });

  it("после reEncryptAll сам VSM читает новым ключом (engine переключён)", async () => {
    await vsm.write("c.md", bytes("payload C"));
    const newEngine = new WebCryptoEngine();
    await newEngine.deriveKey(STUB_EMAIL, "totally different password 123");
    await vsm.reEncryptAll("", newEngine, () => {});
    expect(text(await vsm.read("c.md"))).toBe("payload C");
  });
});
