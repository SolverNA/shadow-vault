/**
 * Тесты утилит fs-utils.
 *
 * Покрытие:
 *   - parallelMap: concurrency, порядок результатов, onItemDone, обработка ошибок
 *   - ensureSymlink/removeSymlink: создание, идемпотентность, защита от перезаписи
 *   - filesEqual: побайтовое сравнение
 *   - isTempFile: фильтрация временных артефактов
 *   - atomicWrite: атомарность через .tmp + rename
 */

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import * as fsp from "fs/promises";
import * as fs from "fs";
import * as nodePath from "path";
import * as os from "os";
import {
  atomicWrite,
  atomicWriteSync,
  ensureSymlink,
  fileExists,
  filesEqual,
  isTempFile,
  listEncryptedDir,
  parallelMap,
  removeSymlink,
  walkDir,
  WalkEntry,
} from "../src/fs-utils";

let tmpBase: string;

beforeEach(() => {
  tmpBase = fs.mkdtempSync(nodePath.join(os.tmpdir(), "sv-fsu-"));
});

afterEach(() => {
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

// ─────────────────────────────────────────────
// parallelMap
// ─────────────────────────────────────────────

describe("parallelMap", () => {
  it("возвращает результаты в исходном порядке", async () => {
    const items = [1, 2, 3, 4, 5];
    const result = await parallelMap(items, 3, async (n) => n * n);
    expect(result).toEqual([1, 4, 9, 16, 25]);
  });

  it("ограничивает concurrency: не больше N параллельно", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);

    await parallelMap(items, 4, async (n) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return n;
    });

    expect(maxInFlight).toBeLessThanOrEqual(4);
    expect(maxInFlight).toBeGreaterThan(1); // действительно параллелим
  });

  it("onItemDone вызывается для каждого элемента", async () => {
    const items = ["a", "b", "c"];
    const seen: number[] = [];
    await parallelMap(items, 2, async (s) => s.toUpperCase(), (idx) => {
      seen.push(idx);
    });
    expect(seen.sort()).toEqual([0, 1, 2]);
  });

  it("пустой массив: возвращает пустой результат, не зависает", async () => {
    const result = await parallelMap([], 4, async () => "never");
    expect(result).toEqual([]);
  });

  it("concurrency=1 эквивалентен sequential", async () => {
    const order: number[] = [];
    await parallelMap([1, 2, 3], 1, async (n) => {
      order.push(n);
      await new Promise((r) => setTimeout(r, 10));
      order.push(n * 10);
    });
    expect(order).toEqual([1, 10, 2, 20, 3, 30]);
  });

  it("ошибка в воркере прерывает parallelMap (Promise.all семантика)", async () => {
    const items = [1, 2, 3];
    await expect(
      parallelMap(items, 2, async (n) => {
        if (n === 2) throw new Error("boom");
        return n;
      })
    ).rejects.toThrow("boom");
  });
});

// ─────────────────────────────────────────────
// ensureSymlink / removeSymlink
// ─────────────────────────────────────────────

describe("ensureSymlink / removeSymlink", () => {
  it("создаёт symlink на существующую папку", async () => {
    const target = nodePath.join(tmpBase, "real-folder");
    fs.mkdirSync(target);
    fs.writeFileSync(nodePath.join(target, "marker.txt"), "found me");

    const link = nodePath.join(tmpBase, "shadow-link");
    await ensureSymlink(target, link);

    // Через симлинк виден файл из target
    expect(fs.readFileSync(nodePath.join(link, "marker.txt"), "utf8")).toBe("found me");
  });

  it("идемпотентно: повторный вызов на существующий симлинк не падает", async () => {
    const target = nodePath.join(tmpBase, "tgt");
    fs.mkdirSync(target);
    const link = nodePath.join(tmpBase, "lnk");

    await ensureSymlink(target, link);
    await expect(ensureSymlink(target, link)).resolves.not.toThrow();
  });

  it("бросает ошибку если linkPath указывает на ДРУГОЙ target", async () => {
    const targetA = nodePath.join(tmpBase, "ta");
    const targetB = nodePath.join(tmpBase, "tb");
    fs.mkdirSync(targetA);
    fs.mkdirSync(targetB);

    const link = nodePath.join(tmpBase, "lnk");
    await ensureSymlink(targetA, link);
    await expect(ensureSymlink(targetB, link)).rejects.toThrow();
  });

  it("бросает ошибку если на месте linkPath не симлинк, а обычная папка", async () => {
    const target = nodePath.join(tmpBase, "real");
    fs.mkdirSync(target);
    const link = nodePath.join(tmpBase, "real-folder-here");
    fs.mkdirSync(link); // не симлинк

    await expect(ensureSymlink(target, link)).rejects.toThrow(/символьной ссылкой/);
  });

  it("removeSymlink удаляет только симлинк (не данные target)", async () => {
    const target = nodePath.join(tmpBase, "data");
    fs.mkdirSync(target);
    fs.writeFileSync(nodePath.join(target, "x"), "x");
    const link = nodePath.join(tmpBase, "link");

    await ensureSymlink(target, link);
    await removeSymlink(link);

    expect(fs.existsSync(link)).toBe(false);
    // target нетронут
    expect(fs.existsSync(nodePath.join(target, "x"))).toBe(true);
  });

  it("removeSymlink на несуществующий путь: молча no-op", async () => {
    await expect(removeSymlink(nodePath.join(tmpBase, "ghost"))).resolves.not.toThrow();
  });

  it("removeSymlink НЕ трогает обычную папку (защита от ошибки)", async () => {
    const realDir = nodePath.join(tmpBase, "real-dir");
    fs.mkdirSync(realDir);
    fs.writeFileSync(nodePath.join(realDir, "file"), "data");

    await removeSymlink(realDir);
    // Папка цела
    expect(fs.existsSync(realDir)).toBe(true);
    expect(fs.existsSync(nodePath.join(realDir, "file"))).toBe(true);
  });
});

// ─────────────────────────────────────────────
// filesEqual
// ─────────────────────────────────────────────

describe("filesEqual", () => {
  it("идентичные файлы: true", async () => {
    const a = nodePath.join(tmpBase, "a");
    const b = nodePath.join(tmpBase, "b");
    fs.writeFileSync(a, "content");
    fs.writeFileSync(b, "content");
    expect(await filesEqual(a, b)).toBe(true);
  });

  it("разный размер: false (без чтения буфера)", async () => {
    const a = nodePath.join(tmpBase, "a");
    const b = nodePath.join(tmpBase, "b");
    fs.writeFileSync(a, "short");
    fs.writeFileSync(b, "longer content");
    expect(await filesEqual(a, b)).toBe(false);
  });

  it("одинаковый размер, разные байты: false", async () => {
    const a = nodePath.join(tmpBase, "a");
    const b = nodePath.join(tmpBase, "b");
    fs.writeFileSync(a, "AAAA");
    fs.writeFileSync(b, "BBBB");
    expect(await filesEqual(a, b)).toBe(false);
  });

  it("оба пустые: true", async () => {
    const a = nodePath.join(tmpBase, "a");
    const b = nodePath.join(tmpBase, "b");
    fs.writeFileSync(a, "");
    fs.writeFileSync(b, "");
    expect(await filesEqual(a, b)).toBe(true);
  });

  it("один из файлов отсутствует: false", async () => {
    const a = nodePath.join(tmpBase, "a");
    fs.writeFileSync(a, "x");
    const b = nodePath.join(tmpBase, "ghost");
    expect(await filesEqual(a, b)).toBe(false);
  });

  it("бинарные данные: 1 байт расхождения → false", async () => {
    const a = nodePath.join(tmpBase, "a");
    const b = nodePath.join(tmpBase, "b");
    fs.writeFileSync(a, Buffer.from([0x01, 0x02, 0x03, 0x04]));
    fs.writeFileSync(b, Buffer.from([0x01, 0x02, 0x99, 0x04]));
    expect(await filesEqual(a, b)).toBe(false);
  });
});

// ─────────────────────────────────────────────
// isTempFile
// ─────────────────────────────────────────────

describe("isTempFile", () => {
  it("распознаёт .tmp", () => {
    expect(isTempFile("note.md.tmp")).toBe(true);
  });

  it("распознаёт .shadowtmp", () => {
    expect(isTempFile("note.md.shadowtmp")).toBe(true);
  });

  it("распознаёт .sessiontmp", () => {
    expect(isTempFile(".session_active.sessiontmp")).toBe(true);
  });

  it("распознаёт .retmp (промежуток re-encrypt)", () => {
    expect(isTempFile("file.enc.retmp")).toBe(true);
  });

  it("распознаёт .enc.new (фаза перешифровки)", () => {
    expect(isTempFile("file.md.enc.new")).toBe(true);
  });

  it("обычные файлы: false", () => {
    expect(isTempFile("note.md")).toBe(false);
    expect(isTempFile("file.enc")).toBe(false);
    expect(isTempFile("img.png")).toBe(false);
  });
});

// ─────────────────────────────────────────────
// atomicWrite
// ─────────────────────────────────────────────

describe("atomicWrite", () => {
  it("создаёт файл с заданным содержимым", async () => {
    const p = nodePath.join(tmpBase, "out.txt");
    await atomicWrite(p, Buffer.from("hello"));
    expect(fs.readFileSync(p, "utf8")).toBe("hello");
  });

  it("перезаписывает существующий файл целиком (не оставляет старого содержимого)", async () => {
    const p = nodePath.join(tmpBase, "out.txt");
    fs.writeFileSync(p, "original-very-long-content-AAAAAAA");
    await atomicWrite(p, Buffer.from("new"));
    expect(fs.readFileSync(p, "utf8")).toBe("new");
    expect(fs.statSync(p).size).toBe(3);
  });

  it("создаёт промежуточные директории", async () => {
    const p = nodePath.join(tmpBase, "deep/nested/dir/file.bin");
    await atomicWrite(p, Buffer.from([0x01, 0x02]));
    expect(await fileExists(p)).toBe(true);
  });

  it("после успешной записи .tmp не остаётся на диске", async () => {
    const p = nodePath.join(tmpBase, "out.txt");
    await atomicWrite(p, Buffer.from("data"));
    expect(await fileExists(p + ".shadowtmp")).toBe(false);
  });

  it("принимает кастомный tmpExt", async () => {
    const p = nodePath.join(tmpBase, "out.txt");
    await atomicWrite(p, Buffer.from("data"), ".sessiontmp");
    expect(fs.readFileSync(p, "utf8")).toBe("data");
    expect(await fileExists(p + ".sessiontmp")).toBe(false);
  });

  it("в каталоге не остаётся никаких временных артефактов (только целевой файл)", async () => {
    // Фиксирует поведение после добавления fsync (файл + каталог):
    // содержимое корректно, а уникальный tmp (<pid>-<ts>-<rnd>.shadowtmp) убран.
    const p = nodePath.join(tmpBase, "out.bin");
    await atomicWrite(p, Buffer.from([0xde, 0xad, 0xbe, 0xef]));
    expect(fs.readFileSync(p).equals(Buffer.from([0xde, 0xad, 0xbe, 0xef]))).toBe(true);
    expect(fs.readdirSync(tmpBase)).toEqual(["out.bin"]);
  });
});

// ─────────────────────────────────────────────
// atomicWriteSync — синхронный вариант для пути закрытия Obsidian
// ─────────────────────────────────────────────

describe("atomicWriteSync", () => {
  it("создаёт файл с заданным содержимым и создаёт промежуточные директории", () => {
    const p = nodePath.join(tmpBase, "deep/sub/out.txt");
    atomicWriteSync(p, Buffer.from("sync-hello"));
    expect(fs.readFileSync(p, "utf8")).toBe("sync-hello");
  });

  it("перезаписывает существующий файл целиком", () => {
    const p = nodePath.join(tmpBase, "out.txt");
    fs.writeFileSync(p, "original-very-long-content-AAAAAAA");
    atomicWriteSync(p, Buffer.from("new"));
    expect(fs.readFileSync(p, "utf8")).toBe("new");
    expect(fs.statSync(p).size).toBe(3);
  });

  it("в каталоге не остаётся временных артефактов", () => {
    const p = nodePath.join(tmpBase, "out.bin");
    atomicWriteSync(p, Buffer.from([0x01, 0x02, 0x03]));
    expect(fs.readdirSync(tmpBase)).toEqual(["out.bin"]);
  });

  it("при ошибке rename подчищает tmp и пробрасывает ошибку", () => {
    // Целевой путь — каталог: renameSync файла поверх непустого каталога падает
    const p = nodePath.join(tmpBase, "target");
    fs.mkdirSync(p);
    fs.writeFileSync(nodePath.join(p, "inner.txt"), "x");
    expect(() => atomicWriteSync(p, Buffer.from("data"))).toThrow();
    expect(fs.readdirSync(tmpBase)).toEqual(["target"]); // tmp убран
  });
});

// ─────────────────────────────────────────────
// walkDir — единый рекурсивный сканер каталогов
// ─────────────────────────────────────────────

describe("walkDir", () => {
  beforeEach(async () => {
    // структура: a.md, sub/b.md, sub/deep/c.md, .hidden/x.md
    fs.writeFileSync(nodePath.join(tmpBase, "a.md"), "a");
    fs.mkdirSync(nodePath.join(tmpBase, "sub", "deep"), { recursive: true });
    fs.writeFileSync(nodePath.join(tmpBase, "sub", "b.md"), "b");
    fs.writeFileSync(nodePath.join(tmpBase, "sub", "deep", "c.md"), "c");
    fs.mkdirSync(nodePath.join(tmpBase, ".hidden"));
    fs.writeFileSync(nodePath.join(tmpBase, ".hidden", "x.md"), "x");
  });

  it("обходит рекурсивно и отдаёт relative-пути через '/'", async () => {
    const files: string[] = [];
    await walkDir(tmpBase, (e: WalkEntry) => {
      if (e.isFile) files.push(e.rel);
      return "recurse";
    });
    expect(files.sort()).toEqual(
      [".hidden/x.md", "a.md", "sub/b.md", "sub/deep/c.md"].sort()
    );
  });

  it("'skip' для каталога не заходит внутрь", async () => {
    const files: string[] = [];
    await walkDir(tmpBase, (e: WalkEntry) => {
      if (e.isDirectory && e.name.startsWith(".")) return "skip";
      if (e.isFile) files.push(e.rel);
      return "recurse";
    });
    expect(files).not.toContain(".hidden/x.md");
    expect(files).toContain("a.md");
    expect(files).toContain("sub/deep/c.md");
  });

  it("несуществующий каталог трактуется как пустой (без throw)", async () => {
    const visited: string[] = [];
    await walkDir(nodePath.join(tmpBase, "nope"), (e) => {
      visited.push(e.rel);
      return "recurse";
    });
    expect(visited).toEqual([]);
  });
});

// ─────────────────────────────────────────────
// listEncryptedDir — единый list-транслятор .enc → имена
// ─────────────────────────────────────────────

describe("listEncryptedDir", () => {
  it("снимает суффикс .enc и пропускает dot/временные файлы", async () => {
    fs.writeFileSync(nodePath.join(tmpBase, "note.md.enc"), "x");
    fs.writeFileSync(nodePath.join(tmpBase, "image.png.enc"), "x");
    fs.writeFileSync(nodePath.join(tmpBase, "plain.md"), "x"); // не .enc — скрываем
    fs.writeFileSync(nodePath.join(tmpBase, ".session_active"), "x");
    fs.writeFileSync(nodePath.join(tmpBase, "tmp.md.enc.shadowtmp"), "x");
    fs.mkdirSync(nodePath.join(tmpBase, "folder"));

    const res = await listEncryptedDir(tmpBase, "", ".obsidian");
    expect(res.files.sort()).toEqual(["image.png", "note.md"].sort());
    expect(res.folders).toEqual(["folder"]);
  });

  it("показывает configDir несмотря на dot-префикс", async () => {
    fs.mkdirSync(nodePath.join(tmpBase, ".obsidian"));
    const res = await listEncryptedDir(tmpBase, "", ".obsidian");
    expect(res.folders).toContain(".obsidian");
  });

  it("проставляет префикс normalizedPath к именам", async () => {
    fs.mkdirSync(nodePath.join(tmpBase, "sub"));
    fs.writeFileSync(nodePath.join(tmpBase, "sub", "n.md.enc"), "x");
    const res = await listEncryptedDir(
      nodePath.join(tmpBase, "sub"),
      "sub",
      ".obsidian"
    );
    expect(res.files).toEqual(["sub/n.md"]);
  });

  it("несуществующий каталог → пустой результат", async () => {
    const res = await listEncryptedDir(
      nodePath.join(tmpBase, "nope"),
      "nope",
      ".obsidian"
    );
    expect(res).toEqual({ files: [], folders: [] });
  });
});
