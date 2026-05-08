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
  ensureSymlink,
  fileExists,
  filesEqual,
  isTempFile,
  parallelMap,
  removeSymlink,
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
});
