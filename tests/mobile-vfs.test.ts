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
import { STUB_EMAIL } from "../src/types";

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
    for (const key of this.files.keys()) {
      if (key.startsWith(prefix) && !key.slice(prefix.length).includes("/")) {
        files.push(key);
      }
    }
    return { files, folders: [] };
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

  it("stat возвращает размер зашифрованного .enc", async () => {
    await vsm.write("s.md", bytes("size me"));
    const st = await vsm.stat("s.md");
    expect(st).not.toBeNull();
    expect(st!.size).toBe(adapter.files.get("s.md.enc")!.byteLength);
  });
});
