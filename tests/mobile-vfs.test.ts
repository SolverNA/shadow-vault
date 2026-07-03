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
import { MobileAdapter, PlatformAdapter } from "../src/platform-adapter";
import { AdapterPatcher } from "../src/adapter-patcher";
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

/**
 * InMemoryAdapter с хуком перед writeBinary — для эмуляции ошибок диска и
 * искусственных задержек (проверка сериализации записей в VSM).
 */
class HookedAdapter extends InMemoryAdapter {
  /** Вызывается ПЕРЕД записью; может бросить (ошибка диска) или подождать. */
  beforeWrite?: (path: string) => void | Promise<void>;
  /** Пути в порядке ФАКТИЧЕСКОГО завершения записи на «диск». */
  completedWrites: string[] = [];

  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    if (this.beforeWrite) await this.beforeWrite(path);
    await super.writeBinary(path, data);
    this.completedWrites.push(path);
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

describe("VirtualShadowManager: сериализация записей и откат кэша при ошибке", () => {
  let hooked: HookedAdapter;
  let v: VirtualShadowManager;

  beforeEach(() => {
    hooked = new HookedAdapter();
    v = new VirtualShadowManager(engine, hooked);
  });

  it("ошибка writeBinary: write бросает, read НЕ отдаёт фантом (прежняя версия с диска)", async () => {
    await v.write("f.md", bytes("v1"));

    hooked.beforeWrite = () => {
      throw Object.assign(new Error("disk full"), { code: "EIO" });
    };
    await expect(v.write("f.md", bytes("v2"))).rejects.toThrow("disk full");
    hooked.beforeWrite = undefined;

    // Кэш инвалидирован: read идёт на диск и возвращает ПРЕЖНЮЮ версию,
    // а не фантомную v2, которой на диске нет.
    expect(text(await v.read("f.md"))).toBe("v1");
    // На диске тоже v1
    expect(text(await engine.decryptBuffer(hooked.files.get("f.md.enc")!))).toBe("v1");

    // Очередь не «отравлена» упавшей записью: следующая запись проходит
    await v.write("f.md", bytes("v3"));
    expect(text(await v.read("f.md"))).toBe("v3");
  });

  it("ошибка writeBinary НОВОГО файла: read даёт ENOENT, exists=false (без фантома)", async () => {
    hooked.beforeWrite = () => Promise.reject(new Error("EIO"));
    await expect(v.write("fresh.md", bytes("ghost"))).rejects.toThrow("EIO");
    hooked.beforeWrite = undefined;

    expect(await v.exists("fresh.md")).toBe(false);
    await expect(v.read("fresh.md")).rejects.toMatchObject({ code: "ENOENT" });
    expect(hooked.files.has("fresh.md.enc")).toBe(false);
  });

  it("параллельные записи одного пути сериализованы: финально ВТОРАЯ версия на диске и в кэше", async () => {
    let releaseFirst!: () => void;
    const gate = new Promise<void>((resolve) => (releaseFirst = resolve));
    let call = 0;
    // Первая запись «зависает» на диске, вторая — быстрая.
    hooked.beforeWrite = async () => {
      if (++call === 1) await gate;
    };

    const p1 = v.write("race.md", bytes("slow-old"));
    const p2 = v.write("race.md", bytes("fast-new"));

    // Даём быстрой записи шанс «обогнать» медленную (без сериализации она
    // завершилась бы здесь, и slow-old затёр бы её на диске после gate).
    await new Promise((r) => setTimeout(r, 20));
    releaseFirst();
    await Promise.all([p1, p2]);

    // На диске финально ВТОРАЯ версия (порядок вызова write сохранён)
    expect(text(await engine.decryptBuffer(hooked.files.get("race.md.enc")!))).toBe("fast-new");
    expect(hooked.completedWrites).toEqual(["race.md.enc", "race.md.enc"]);
    // В кэше тоже вторая
    expect(text(await v.read("race.md"))).toBe("fast-new");
    // И холодное чтение (без кэша) подтверждает диск
    const fresh = new VirtualShadowManager(engine, hooked);
    expect(text(await fresh.read("race.md"))).toBe("fast-new");
  });

  it("параллельные записи РАЗНЫХ путей не блокируют друг друга", async () => {
    let releaseA!: () => void;
    const gateA = new Promise<void>((resolve) => (releaseA = resolve));
    hooked.beforeWrite = async (path) => {
      if (path === "a.md.enc") await gateA;
    };

    const done: string[] = [];
    const pA = v.write("a.md", bytes("A")).then(() => done.push("a"));
    const pB = v.write("b.md", bytes("B")).then(() => done.push("b"));

    // b.md завершается, пока a.md ещё висит на «диске» — очереди per-path
    await pB;
    expect(done).toEqual(["b"]);
    expect(hooked.files.has("b.md.enc")).toBe(true);
    expect(hooked.files.has("a.md.enc")).toBe(false);

    releaseA();
    await pA;
    expect(done).toEqual(["b", "a"]);
    expect(text(await v.read("a.md"))).toBe("A");
  });

  it("remove в очереди с write: не обгоняет висящую запись того же пути", async () => {
    await v.write("q.md", bytes("first"));

    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let gated = true;
    hooked.beforeWrite = async () => {
      if (gated) await gate;
    };

    const pWrite = v.write("q.md", bytes("second"));
    const pRemove = v.remove("q.md"); // встаёт в очередь ПОСЛЕ записи

    await new Promise((r) => setTimeout(r, 20));
    // remove ещё не выполнился: он ждёт завершения висящей записи
    expect(hooked.files.has("q.md.enc")).toBe(true);

    gated = false;
    release();
    await Promise.all([pWrite, pRemove]);

    // Итог по порядку вызовов: записали second, затем удалили — файла нет
    expect(hooked.files.has("q.md.enc")).toBe(false);
    expect(await v.exists("q.md")).toBe(false);
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

describe("VirtualShadowManager.exportToPlaintext (отключение шифрования на mobile)", () => {
  it("расшифровывает все .enc в plaintext и удаляет .enc", async () => {
    await vsm.write("a.md", bytes("alpha"));
    await vsm.write("dir/b.md", bytes("beta"));

    const progress: Array<[number, number, string]> = [];
    const res = await vsm.exportToPlaintext(".obsidian", (d, t, c) => progress.push([d, t, c]));

    expect(res.failed).toHaveLength(0);
    expect(res.skippedOrphans).toHaveLength(0);
    expect(res.exported.sort()).toEqual(["a.md", "dir/b.md"]);
    // plaintext на месте
    expect(text(adapter.files.get("a.md")!)).toBe("alpha");
    expect(text(adapter.files.get("dir/b.md")!)).toBe("beta");
    // .enc удалены батчем в конце
    expect(adapter.files.has("a.md.enc")).toBe(false);
    expect(adapter.files.has("dir/b.md.enc")).toBe(false);
    expect(progress.length).toBeGreaterThan(0);
  });

  it("холодный экспорт (пустой кэш) расшифровывает строго из .enc", async () => {
    await vsm.write("cold.md", bytes("cold payload"));

    // Свежий VSM без прогретого кэша — как после перезапуска приложения.
    const fresh = new VirtualShadowManager(engine, adapter);
    const res = await fresh.exportToPlaintext(".obsidian");

    expect(res.failed).toHaveLength(0);
    expect(text(adapter.files.get("cold.md")!)).toBe("cold payload");
    expect(adapter.files.has("cold.md.enc")).toBe(false);
  });

  it("нерасшифрованный .enc (orphan) остаётся на диске и попадает в skippedOrphans", async () => {
    await vsm.write("good.md", bytes("ok"));
    // Битый .enc: мусор вместо шифртекста — расшифровка провалится.
    const garbage = bytes("это не валидный шифртекст вообще");
    adapter.files.set("broken.md.enc", garbage);

    const res = await vsm.exportToPlaintext(".obsidian");

    expect(res.failed).toHaveLength(0);
    expect(res.exported).toEqual(["good.md"]);
    expect(res.skippedOrphans).toEqual(["broken.md"]);
    // Экспортированный: plaintext на месте, .enc удалён
    expect(text(adapter.files.get("good.md")!)).toBe("ok");
    expect(adapter.files.has("good.md.enc")).toBe(false);
    // КРИТИЧНО: orphan .enc — единственная копия данных — НЕ удалён,
    // и его «plaintext» не появился
    expect(adapter.files.get("broken.md.enc")).toBe(garbage);
    expect(adapter.files.has("broken.md")).toBe(false);
  });

  it("гейтит write во время экспорта: правка попадает в plaintext, .enc не воскрешает", async () => {
    await vsm.write("a.md", bytes("v1"));
    await vsm.write("b.md", bytes("v2"));

    // Правка «a.md» прилетает ПОСЕРЕДИНЕ экспорта — до фикса write писал бы
    // свежий a.md.enc, который фаза 2 тут же удаляла (потеря правки).
    let injected = false;
    const res = await vsm.exportToPlaintext("", (d) => {
      if (!injected && d >= 1) {
        injected = true;
        void vsm.write("a.md", bytes("edited-during-export"));
      }
    });

    expect(injected).toBe(true);
    expect(res.failed).toHaveLength(0);
    // Правка НЕ потеряна: дописана plaintext'ом из кэша (фаза 1.5)
    expect(text(adapter.files.get("a.md")!)).toBe("edited-during-export");
    expect(text(adapter.files.get("b.md")!)).toBe("v2");
    // .enc удалены и не воскрешены отложенной записью
    expect(adapter.files.has("a.md.enc")).toBe(false);
    expect(adapter.files.has("b.md.enc")).toBe(false);

    // Гейт остаётся после успеха: поздняя запись (до unpatch в main) не
    // создаёт новый .enc в уже расшифрованном хранилище.
    await vsm.write("a.md", bytes("late-write"));
    expect(adapter.files.has("a.md.enc")).toBe(false);
  });

  it("при СБОЕ экспорта .enc не удаляются, а отложенные записи дошифровываются в .enc", async () => {
    const hooked = new HookedAdapter();
    const v = new VirtualShadowManager(engine, hooked);
    await v.write("a.md", bytes("va"));
    await v.write("b.md", bytes("vb"));

    // Ломаем запись plaintext ТОЛЬКО для a.md (.enc-записи проходят).
    hooked.beforeWrite = (path) => {
      if (path === "a.md") throw new Error("disk full");
    };

    let injected = false;
    const res = await v.exportToPlaintext("", (d) => {
      if (!injected && d >= 1) {
        injected = true;
        void v.write("b.md", bytes("deferred-edit")); // отложится гейтом
      }
    });

    expect(injected).toBe(true);
    expect(res.failed.map((f) => f.path)).toContain("a.md");
    // Фаза 2 не выполнялась: оба .enc на диске
    expect(hooked.files.has("a.md.enc")).toBe(true);
    expect(hooked.files.has("b.md.enc")).toBe(true);
    // Шифрование остаётся включённым → отложенная правка дошифрована в .enc
    expect(text(await engine.decryptBuffer(hooked.files.get("b.md.enc")!))).toBe("deferred-edit");
    // Гейт снят: обычные записи снова идут в .enc
    await v.write("c.md", bytes("after-fail"));
    expect(hooked.files.has("c.md.enc")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Интеграция РЕАЛЬНОЙ связки AdapterPatcher + MobileAdapter + VSM
// (регрессия: до фикса MobileAdapter звал патченные методы адаптера →
//  бесконечная рекурсия / stack overflow на любом read/list)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Fake Obsidian DataAdapter: один и тот же объект — и цель патча
 * (AdapterPatcher.patch), и источник оригинальных методов для MobileAdapter,
 * ровно как реальный vault.adapter на mobile.
 */
class FakeDataAdapter {
  files = new Map<string, ArrayBuffer>();
  dirs = new Set<string>();
  /** «Корзина»: сюда trashLocal/trashSystem переносят файлы (null — папка). */
  trashed = new Map<string, ArrayBuffer | null>();
  /** Журналы вызовов — для проверки атомарности rename (нет write+remove). */
  renameCalls: Array<[string, string]> = [];
  writeBinaryCalls: string[] = [];
  removeCalls: string[] = [];

  async read(path: string): Promise<string> {
    return text(await this.readBinary(path));
  }
  async readBinary(path: string): Promise<ArrayBuffer> {
    const v = this.files.get(path);
    if (!v) throw Object.assign(new Error("ENOENT: " + path), { code: "ENOENT" });
    return v;
  }
  async write(path: string, data: string): Promise<void> {
    await this.writeBinary(path, bytes(data));
  }
  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    this.writeBinaryCalls.push(path);
    this.files.set(path, data);
  }
  async append(path: string, data: string): Promise<void> {
    const cur = this.files.get(path);
    this.files.set(path, bytes((cur ? text(cur) : "") + data));
  }
  async appendBinary(path: string, data: ArrayBuffer): Promise<void> {
    const cur = this.files.get(path) ?? new ArrayBuffer(0);
    const joined = new Uint8Array(cur.byteLength + data.byteLength);
    joined.set(new Uint8Array(cur), 0);
    joined.set(new Uint8Array(data), cur.byteLength);
    this.files.set(path, joined.buffer);
  }
  async process(path: string, fn: (data: string) => string): Promise<string> {
    const cur = this.files.get(path);
    if (!cur) throw Object.assign(new Error("ENOENT: " + path), { code: "ENOENT" });
    const result = fn(text(cur));
    this.files.set(path, bytes(result));
    return result;
  }
  async exists(path: string): Promise<boolean> {
    return this.files.has(path) || this.dirs.has(path);
  }
  async remove(path: string): Promise<void> {
    this.removeCalls.push(path);
    if (!this.files.delete(path)) {
      throw Object.assign(new Error("ENOENT: " + path), { code: "ENOENT" });
    }
  }
  async rmdir(path: string, _recursive: boolean): Promise<void> {
    this.dirs.delete(path);
    for (const k of [...this.files.keys()]) {
      if (k.startsWith(path + "/")) this.files.delete(k);
    }
    for (const d of [...this.dirs]) {
      if (d.startsWith(path + "/")) this.dirs.delete(d);
    }
  }
  async rename(oldPath: string, newPath: string): Promise<void> {
    this.renameCalls.push([oldPath, newPath]);
    const v = this.files.get(oldPath);
    if (v) {
      this.files.delete(oldPath);
      this.files.set(newPath, v);
      return;
    }
    // Папка: переносим её саму, все файлы и подпапки (как нативный rename)
    if (this.dirs.has(oldPath)) {
      this.dirs.delete(oldPath);
      this.dirs.add(newPath);
      for (const k of [...this.files.keys()]) {
        if (k.startsWith(oldPath + "/")) {
          this.files.set(newPath + k.slice(oldPath.length), this.files.get(k)!);
          this.files.delete(k);
        }
      }
      for (const d of [...this.dirs]) {
        if (d.startsWith(oldPath + "/")) {
          this.dirs.delete(d);
          this.dirs.add(newPath + d.slice(oldPath.length));
        }
      }
      return;
    }
    throw Object.assign(new Error("ENOENT: " + oldPath), { code: "ENOENT" });
  }
  async trashLocal(path: string): Promise<void> {
    if (!(await this.moveToTrash(path))) {
      throw Object.assign(new Error("ENOENT: " + path), { code: "ENOENT" });
    }
  }
  async trashSystem(path: string): Promise<boolean> {
    return this.moveToTrash(path);
  }
  private async moveToTrash(path: string): Promise<boolean> {
    const v = this.files.get(path);
    if (v) {
      this.files.delete(path);
      this.trashed.set(path, v);
      return true;
    }
    if (this.dirs.has(path)) {
      this.dirs.delete(path);
      this.trashed.set(path, null);
      for (const k of [...this.files.keys()]) {
        if (k.startsWith(path + "/")) {
          this.trashed.set(k, this.files.get(k)!);
          this.files.delete(k);
        }
      }
      for (const d of [...this.dirs]) {
        if (d.startsWith(path + "/")) this.dirs.delete(d);
      }
      return true;
    }
    return false;
  }
  async copy(src: string, dst: string): Promise<void> {
    const v = this.files.get(src);
    if (!v) throw Object.assign(new Error("ENOENT: " + src), { code: "ENOENT" });
    this.files.set(dst, v.slice(0));
  }
  async mkdir(path: string): Promise<void> {
    this.dirs.add(path);
  }
  async stat(
    path: string
  ): Promise<{ type: "file" | "folder"; ctime: number; mtime: number; size: number } | null> {
    const v = this.files.get(path);
    if (v) return { type: "file", ctime: 1000, mtime: 1000, size: v.byteLength };
    if (this.dirs.has(path)) return { type: "folder", ctime: 1000, mtime: 1000, size: 0 };
    return null;
  }
  async list(path: string): Promise<{ files: string[]; folders: string[] }> {
    const prefix = path ? path + "/" : "";
    const files: string[] = [];
    const folders = new Set<string>();
    for (const key of this.files.keys()) {
      if (!key.startsWith(prefix)) continue;
      const rest = key.slice(prefix.length);
      const slash = rest.indexOf("/");
      if (slash === -1) files.push(key);
      else folders.add(prefix + rest.slice(0, slash));
    }
    for (const d of this.dirs) {
      if (d !== path && d.startsWith(prefix) && !d.slice(prefix.length).includes("/")) {
        folders.add(d);
      }
    }
    return { files, folders: [...folders] };
  }
}

describe("Интеграция AdapterPatcher + MobileAdapter + VSM (без рекурсии)", () => {
  let fake: FakeDataAdapter;
  let mobile: MobileAdapter;
  let ivsm: VirtualShadowManager;
  let patcher: AdapterPatcher;

  beforeEach(() => {
    fake = new FakeDataAdapter();
    // Порядок как в main.onUnlockMobile: MobileAdapter создаётся ДО patch()
    // и захватывает ОРИГИНАЛЬНЫЕ методы адаптера в конструкторе.
    mobile = new MobileAdapter({ adapter: fake } as any);
    ivsm = new VirtualShadowManager(engine, mobile);
    patcher = new AdapterPatcher(ivsm, ".obsidian");
    patcher.patch(fake as any);
  });

  it("write/read через патченный адаптер: .enc (v2) на диске, plaintext читается", async () => {
    await fake.write("notes/note.md", "hello mobile");

    // На «диске» — только .enc в формате v2, plaintext-файла нет
    expect(fake.files.has("notes/note.md")).toBe(false);
    const enc = fake.files.get("notes/note.md.enc");
    expect(enc).toBeTruthy();
    expect(isV2(new Uint8Array(enc!))).toBe(true);

    // Патченный read расшифровывает обратно (до фикса — stack overflow)
    expect(await fake.read("notes/note.md")).toBe("hello mobile");
  });

  it("read холодного файла (пустой кэш) идёт в оригинальный readBinary", async () => {
    await fake.write("cold.md", "cold data");
    ivsm.clearCache(); // имитация перезапуска: чтение строго из .enc
    expect(await fake.read("cold.md")).toBe("cold data");
  });

  it("list через патченный адаптер не рекурсирует и убирает .enc из имён", async () => {
    await fake.write("notes/a.md", "A");
    await fake.write("notes/b.md", "B");
    // До фикса: patchedList → vsm.list → mobile.list → patchedList → ∞
    const res = await fake.list("notes");
    expect(res.files.sort()).toEqual(["notes/a.md", "notes/b.md"]);
  });

  it("exists/stat/remove/rename работают сквозь связку", async () => {
    await fake.write("f.md", "payload");
    expect(await fake.exists("f.md")).toBe(true);

    const st = await fake.stat("f.md");
    expect(st).not.toBeNull();
    expect(st!.size).toBe("payload".length); // размер plaintext, не .enc

    await fake.rename("f.md", "g.md");
    expect(fake.files.has("f.md.enc")).toBe(false);
    expect(await fake.read("g.md")).toBe("payload");

    await fake.remove("g.md");
    expect(await fake.exists("g.md")).toBe(false);
    expect(fake.files.has("g.md.enc")).toBe(false);
  });

  it("list('') корня транслирует имена: note.md, а не note.md.enc (регрессия root-bypass)", async () => {
    await fake.write("root-note.md", "root payload");
    await fake.write(".obsidian/app.json", "{}");

    // До фикса isVaultRoot: patchedList("") уходил в bypass ("" ∈ isBypassPath)
    // и отдавал сырой .enc-листинг → индекс vault строился по неверным именам.
    const res = await fake.list("");
    expect(res.files).toContain("root-note.md");
    expect(res.files.some((f) => f.endsWith(".enc"))).toBe(false);
    // Служебная папка конфигурации не пропадает из листинга корня
    expect(res.folders).toContain(".obsidian");

    // Варианты нормализации корня ("/" и ".") транслируются так же, как ""
    for (const root of ["/", "."]) {
      const r = await fake.list(root);
      expect(r.files).toContain("root-note.md");
      expect(r.files.some((f) => f.endsWith(".enc"))).toBe(false);
    }
  });

  // ── Регрессия: утечка plaintext через непропатченные append/process ─────
  it("append к существующему файлу: содержимое дописано, на диске только .enc", async () => {
    await fake.write("ap.md", "line1\n");
    await fake.append("ap.md", "line2\n");

    // На «диске» нет открытого plaintext-файла — только .enc
    expect(fake.files.has("ap.md")).toBe(false);
    const enc = fake.files.get("ap.md.enc");
    expect(enc).toBeTruthy();
    expect(isV2(new Uint8Array(enc!))).toBe(true);
    expect(text(enc!)).not.toContain("line1");

    expect(await fake.read("ap.md")).toBe("line1\nline2\n");
  });

  it("append к несуществующему файлу создаёт .enc, а не plaintext", async () => {
    await fake.append("new-daily.md", "первая запись");

    expect(fake.files.has("new-daily.md")).toBe(false);
    const enc = fake.files.get("new-daily.md.enc");
    expect(enc).toBeTruthy();
    expect(isV2(new Uint8Array(enc!))).toBe(true);

    expect(await fake.read("new-daily.md")).toBe("первая запись");
  });

  it("append читается и после сброса кэша (данные реально в .enc)", async () => {
    await fake.write("cold-ap.md", "a");
    await fake.append("cold-ap.md", "b");
    ivsm.clearCache(); // имитация перезапуска: чтение строго из .enc
    expect(await fake.read("cold-ap.md")).toBe("ab");
  });

  it("appendBinary дописывает бинарные данные через VSM без plaintext на диске", async () => {
    await fake.write("bin.md", "AB");
    await fake.appendBinary("bin.md", bytes("CD"));

    expect(fake.files.has("bin.md")).toBe(false);
    const enc = fake.files.get("bin.md.enc");
    expect(enc).toBeTruthy();
    expect(isV2(new Uint8Array(enc!))).toBe(true);
    expect(await fake.read("bin.md")).toBe("ABCD");
  });

  it("process: применяет fn, возвращает результат, пишет зашифрованно", async () => {
    await fake.write("fm.md", "---\ntags: []\n---\nbody");

    const returned = await fake.process("fm.md", (data) =>
      data.replace("tags: []", "tags: [x]")
    );

    // Возврат — НОВОЕ содержимое (семантика Obsidian process)
    expect(returned).toBe("---\ntags: [x]\n---\nbody");

    // На «диске» — только .enc, plaintext не появился
    expect(fake.files.has("fm.md")).toBe(false);
    const enc = fake.files.get("fm.md.enc")!;
    expect(isV2(new Uint8Array(enc))).toBe(true);
    expect(text(enc)).not.toContain("tags: [x]");

    // Результат применён и читается обратно (в т.ч. после сброса кэша)
    ivsm.clearCache();
    expect(await fake.read("fm.md")).toBe("---\ntags: [x]\n---\nbody");
  });

  it("append/process в bypass (.obsidian) идут в оригинал без шифрования", async () => {
    await fake.append(".obsidian/log.txt", "raw-log");
    expect(text(fake.files.get(".obsidian/log.txt")!)).toBe("raw-log");
    expect(fake.files.has(".obsidian/log.txt.enc")).toBe(false);

    const out = await fake.process(".obsidian/log.txt", (d) => d + "!");
    expect(out).toBe("raw-log!");
    expect(text(fake.files.get(".obsidian/log.txt")!)).toBe("raw-log!");
  });

  it("bypass: .obsidian идёт напрямую без шифрования", async () => {
    await fake.write(".obsidian/app.json", "{}");
    expect(text(fake.files.get(".obsidian/app.json")!)).toBe("{}");
    expect(fake.files.has(".obsidian/app.json.enc")).toBe(false);
    expect(await fake.read(".obsidian/app.json")).toBe("{}");
  });

  it("unpatch возвращает адаптер в исходное поведение", async () => {
    patcher.unpatch(fake as any);
    await fake.write("plain.md", "raw");
    expect(text(fake.files.get("plain.md")!)).toBe("raw");
    expect(fake.files.has("plain.md.enc")).toBe(false);
  });

  it("unpatch восстанавливает оригинальные append/appendBinary/process", async () => {
    patcher.unpatch(fake as any);

    // append — нативный: plaintext на диске, без .enc
    await fake.append("plain-ap.md", "raw-append");
    expect(text(fake.files.get("plain-ap.md")!)).toBe("raw-append");
    expect(fake.files.has("plain-ap.md.enc")).toBe(false);

    // appendBinary — нативный
    await fake.appendBinary("plain-ap.md", bytes("+bin"));
    expect(text(fake.files.get("plain-ap.md")!)).toBe("raw-append+bin");

    // process — нативный: работает по plaintext-файлу напрямую
    const out = await fake.process("plain-ap.md", (d) => d.toUpperCase());
    expect(out).toBe("RAW-APPEND+BIN");
    expect(text(fake.files.get("plain-ap.md")!)).toBe("RAW-APPEND+BIN");
    expect(fake.files.has("plain-ap.md.enc")).toBe(false);
  });

  it("цикл lock/unlock (unpatch → новая связка → patch) не наслаивает патчи", async () => {
    await fake.write("n.md", "v1");
    patcher.unpatch(fake as any);

    // Новая сессия: новый MobileAdapter захватывает восстановленные оригиналы
    const mobile2 = new MobileAdapter({ adapter: fake } as any);
    const vsm2 = new VirtualShadowManager(engine, mobile2);
    const patcher2 = new AdapterPatcher(vsm2, ".obsidian");
    patcher2.patch(fake as any);

    expect(await fake.read("n.md")).toBe("v1");
    await fake.write("n.md", "v2");
    expect(await fake.read("n.md")).toBe("v2");
    // На диске один слой шифрования: .enc расшифровывается движком напрямую
    expect(text(await engine.decryptBuffer(fake.files.get("n.md.enc")!))).toBe("v2");
  });

  it("reEncryptAll на патченном адаптере пишет в ОРИГИНАЛ (без двойного шифрования)", async () => {
    await fake.write("r.md", "re-encrypt me");

    const newEngine = new WebCryptoEngine();
    await newEngine.deriveKey(STUB_EMAIL, "brand new password 42");
    await ivsm.reEncryptAll(".obsidian", newEngine);

    // Ровно один слой шифрования НОВЫМ ключом (до фикса запись шла через
    // патченный writeBinary → двойное шифрование и r.md.enc.enc)
    expect(fake.files.has("r.md.enc.enc")).toBe(false);
    const enc = fake.files.get("r.md.enc")!;
    expect(text(await newEngine.decryptBuffer(enc))).toBe("re-encrypt me");
  });

  // ── Папки: stat/exists/remove/rename не должны транслироваться в .enc ───
  it("stat/exists папки идут в оригинал: папка видна как folder (не null/false)", async () => {
    await fake.mkdir("folder");
    await fake.write("folder/inner.md", "data");

    // До фикса: stat("folder") искал "folder.enc" → null, exists → false
    const st = await fake.stat("folder");
    expect(st).not.toBeNull();
    expect(st!.type).toBe("folder");
    expect(await fake.exists("folder")).toBe(true);

    // Файл внутри папки при этом остаётся «файлом» с plaintext-размером
    const fst = await fake.stat("folder/inner.md");
    expect(fst!.type).toBe("file");
    expect(fst!.size).toBe("data".length);
  });

  it("remove папки удаляет её рекурсивно вместе с .enc внутри (без воскрешения)", async () => {
    await fake.mkdir("folder");
    await fake.write("folder/a.md", "A");
    await fake.write("folder/b.md", "B");
    expect(fake.files.has("folder/a.md.enc")).toBe(true);

    // До фикса: remove("folder") → MobileAdapter.remove("folder.enc") — no-op,
    // папка и .enc оставались и «воскресали» в UI.
    await fake.remove("folder");

    expect(fake.dirs.has("folder")).toBe(false);
    expect(fake.files.has("folder/a.md.enc")).toBe(false);
    expect(fake.files.has("folder/b.md.enc")).toBe(false);
    // Кэш VSM инвалидирован: файлы не воскресают из памяти
    expect(await fake.exists("folder/a.md")).toBe(false);
    await expect(fake.read("folder/a.md")).rejects.toBeTruthy();
  });

  it("rmdir инвалидирует кэш VSM по префиксу", async () => {
    await fake.mkdir("d");
    await fake.write("d/x.md", "X"); // попадает в кэш VSM
    await fake.rmdir("d", true);
    expect(await fake.exists("d/x.md")).toBe(false);
    await expect(fake.read("d/x.md")).rejects.toBeTruthy();
  });

  it("rename папки — проброс в оригинал: файлы читаются по новым путям, кэш не отдаёт старьё", async () => {
    await fake.mkdir("dir");
    await fake.write("dir/a.md", "payload A");
    await fake.write("dir/sub/b.md", "payload B");

    // До фикса: rename("dir", ...) падал на readBinary("dir.enc")
    await fake.rename("dir", "dir2");

    expect(fake.dirs.has("dir")).toBe(false);
    expect(fake.dirs.has("dir2")).toBe(true);
    expect(fake.files.has("dir/a.md.enc")).toBe(false);
    expect(fake.files.has("dir2/a.md.enc")).toBe(true);

    // Содержимое читается по новым путям (расшифровка из переехавших .enc)
    expect(await fake.read("dir2/a.md")).toBe("payload A");
    expect(await fake.read("dir2/sub/b.md")).toBe("payload B");

    // Старые пути не воскресают из кэша VSM
    expect(await fake.exists("dir/a.md")).toBe(false);
    await expect(fake.read("dir/a.md")).rejects.toBeTruthy();
  });

  it("rename файла атомарен: нативный rename .enc→.enc, без read+write+remove", async () => {
    await fake.write("at.md", "atomic payload");

    fake.renameCalls.length = 0;
    const writesBefore = fake.writeBinaryCalls.length;
    const removesBefore = fake.removeCalls.length;

    await fake.rename("at.md", "bt.md");

    // Ровно один нативный rename шифртекста, имена транслированы
    expect(fake.renameCalls).toEqual([["at.md.enc", "bt.md.enc"]]);
    // Неатомарного пути (write нового + remove старого) НЕ было
    expect(fake.writeBinaryCalls.length).toBe(writesBefore);
    expect(fake.removeCalls.length).toBe(removesBefore);

    expect(fake.files.has("at.md.enc")).toBe(false);
    // Запись кэша VSM переехала и данные реально на диске (после сброса кэша)
    expect(await fake.read("bt.md")).toBe("atomic payload");
    ivsm.clearCache();
    expect(await fake.read("bt.md")).toBe("atomic payload");
  });

  // ── trashLocal/trashSystem: перехват с трансляцией имени файла ──────────
  it("trashLocal файла отправляет .enc в корзину (до фикса — ENOENT по plaintext-имени)", async () => {
    await fake.write("t.md", "trash me");

    await fake.trashLocal("t.md");

    // В корзине лежит .enc (имя с .enc — приемлемый компромисс)
    expect(fake.trashed.has("t.md.enc")).toBe(true);
    expect(fake.files.has("t.md.enc")).toBe(false);
    // Кэш VSM инвалидирован
    expect(await fake.exists("t.md")).toBe(false);
  });

  it("trashSystem файла — .enc в системную корзину; trash папки — проброс как есть", async () => {
    await fake.write("s.md", "sys");
    expect(await fake.trashSystem("s.md")).toBe(true);
    expect(fake.trashed.has("s.md.enc")).toBe(true);
    expect(await fake.exists("s.md")).toBe(false);

    // Папка уезжает в корзину под своим именем, содержимое — вместе с ней
    await fake.mkdir("tf");
    await fake.write("tf/x.md", "X");
    await fake.trashLocal("tf");
    expect(fake.dirs.has("tf")).toBe(false);
    expect(fake.trashed.has("tf")).toBe(true);
    expect(fake.trashed.has("tf/x.md.enc")).toBe(true);
    // Кэш VSM инвалидирован по префиксу папки
    expect(await fake.exists("tf/x.md")).toBe(false);
  });

  it("trash в bypass (.obsidian) идёт в оригинал без трансляции имён", async () => {
    await fake.write(".obsidian/junk.json", "{}");
    await fake.trashLocal(".obsidian/junk.json");
    expect(fake.trashed.has(".obsidian/junk.json")).toBe(true);
    expect(fake.trashed.has(".obsidian/junk.json.enc")).toBe(false);
  });
});
