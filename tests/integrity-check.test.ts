/**
 * Тесты двухэтапной проверки целостности.
 *
 * Этап 1 (semantic): сравнение shadow с расшифрованным оригиналом побайтово.
 * Этап 2 (integrity): UTF-8 валидность для текста, magic bytes для бинарников.
 */

import { describe, it, expect } from "@jest/globals";
import { checkFileIntegrity, compareSemantic } from "../src/integrity-check";

describe("compareSemantic — Этап 1", () => {
  it("равные буферы: kind=equal", () => {
    const a = Buffer.from("hello world", "utf8");
    const b = Buffer.from("hello world", "utf8");
    const r = compareSemantic(a, b);
    expect(r.kind).toBe("equal");
  });

  it("разный размер: kind=different с указанием Δ", () => {
    const a = Buffer.from("hello world", "utf8");
    const b = Buffer.from("hello world!", "utf8");
    const r = compareSemantic(a, b);
    expect(r.kind).toBe("different");
    if (r.kind === "different") {
      expect(r.reason).toContain("shadow=11");
      expect(r.reason).toContain("original=12");
      expect(r.reason).toContain("Δ=1");
    }
  });

  it("одинаковый размер, разный контент: kind=different", () => {
    const a = Buffer.from("aaaa", "utf8");
    const b = Buffer.from("bbbb", "utf8");
    const r = compareSemantic(a, b);
    expect(r.kind).toBe("different");
  });

  it("оригинал отсутствует (null): kind=original-missing", () => {
    const a = Buffer.from("anything", "utf8");
    const r = compareSemantic(a, null);
    expect(r.kind).toBe("original-missing");
  });

  it("пустые буферы равны", () => {
    const r = compareSemantic(Buffer.alloc(0), Buffer.alloc(0));
    expect(r.kind).toBe("equal");
  });

  it("бинарные равные буферы", () => {
    const a = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff]);
    const b = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff]);
    expect(compareSemantic(a, b).kind).toBe("equal");
  });
});

describe("checkFileIntegrity — Этап 2: текстовые форматы", () => {
  it(".md с валидной UTF-8: ok=true", () => {
    const buf = Buffer.from("# Заголовок\n\nТекст с emoji 🔐 и кириллицей.", "utf8");
    expect(checkFileIntegrity("note.md", buf)).toEqual({ ok: true });
  });

  it(".md с битой UTF-8 (одиночный 0x80): ok=false", () => {
    // 0x80 — стартовый байт продолжения без префикса → невалидный UTF-8
    const buf = Buffer.from([0x68, 0x65, 0x80, 0x6c, 0x6f]);
    const r = checkFileIntegrity("note.md", buf);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("UTF-8");
  });

  it(".json с валидной UTF-8: ok=true", () => {
    const buf = Buffer.from('{"key": "value"}', "utf8");
    expect(checkFileIntegrity("data.json", buf)).toEqual({ ok: true });
  });

  it(".txt c U+FFFD replacement char (явный артефакт битой кодировки): ok=false", () => {
    const buf = Buffer.from("hello � world", "utf8");
    const r = checkFileIntegrity("note.txt", buf);
    expect(r.ok).toBe(false);
  });

  it("пустой файл с любым расширением: ok=true", () => {
    expect(checkFileIntegrity("empty.md", Buffer.alloc(0))).toEqual({ ok: true });
    expect(checkFileIntegrity("empty.png", Buffer.alloc(0))).toEqual({ ok: true });
  });
});

describe("checkFileIntegrity — Этап 2: бинарные форматы", () => {
  it(".png с валидным magic: ok=true", () => {
    const png = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      Buffer.from([0x00, 0x00, 0x00, 0x0d]), // дальше любой контент
    ]);
    expect(checkFileIntegrity("img.png", png)).toEqual({ ok: true });
  });

  it(".png с битым magic: ok=false", () => {
    const fake = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const r = checkFileIntegrity("img.png", fake);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("magic bytes");
  });

  it(".jpg / .jpeg валидный: ok=true", () => {
    const jpg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff]), Buffer.alloc(100)]);
    expect(checkFileIntegrity("a.jpg", jpg)).toEqual({ ok: true });
    expect(checkFileIntegrity("a.jpeg", jpg)).toEqual({ ok: true });
  });

  it(".pdf: проверяем %PDF-", () => {
    const pdf = Buffer.from("%PDF-1.4\n...", "ascii");
    expect(checkFileIntegrity("doc.pdf", pdf)).toEqual({ ok: true });

    const fake = Buffer.from("hello", "ascii");
    expect(checkFileIntegrity("doc.pdf", fake).ok).toBe(false);
  });

  it(".gif: GIF87a и GIF89a оба валидны", () => {
    const gif87 = Buffer.from("GIF87a..........", "ascii");
    const gif89 = Buffer.from("GIF89a..........", "ascii");
    expect(checkFileIntegrity("a.gif", gif87)).toEqual({ ok: true });
    expect(checkFileIntegrity("a.gif", gif89)).toEqual({ ok: true });
  });

  it(".zip / .docx / .xlsx (PK архивы): валидный magic", () => {
    const pk = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(100)]);
    expect(checkFileIntegrity("a.zip", pk)).toEqual({ ok: true });
    expect(checkFileIntegrity("a.docx", pk)).toEqual({ ok: true });
    expect(checkFileIntegrity("a.xlsx", pk)).toEqual({ ok: true });
  });

  it(".mp4: ftyp на смещении 4", () => {
    const mp4 = Buffer.concat([
      Buffer.from([0x00, 0x00, 0x00, 0x18]),
      Buffer.from("ftyp", "ascii"),
      Buffer.alloc(50),
    ]);
    expect(checkFileIntegrity("v.mp4", mp4)).toEqual({ ok: true });

    const fake = Buffer.alloc(20);
    expect(checkFileIntegrity("v.mp4", fake).ok).toBe(false);
  });

  it(".mp3 с ID3-тегом: ok=true", () => {
    const mp3 = Buffer.concat([Buffer.from([0x49, 0x44, 0x33]), Buffer.alloc(50)]);
    expect(checkFileIntegrity("song.mp3", mp3)).toEqual({ ok: true });
  });

  it("слишком короткий бинарник для magic check: ok=false", () => {
    const tooShort = Buffer.from([0x89]); // PNG ожидает 8 байт magic
    const r = checkFileIntegrity("img.png", tooShort);
    expect(r.ok).toBe(false);
  });
});

describe("checkFileIntegrity — неизвестные форматы", () => {
  it("неизвестное расширение и непустое содержимое: ok=true (нечем проверять)", () => {
    const buf = Buffer.from([0x42, 0x42, 0x42]);
    expect(checkFileIntegrity("file.xyz", buf)).toEqual({ ok: true });
  });

  it("файл без расширения: ok=true", () => {
    expect(checkFileIntegrity("README", Buffer.from("hello"))).toEqual({ ok: true });
  });

  it("вложенный путь: расширение определяется корректно", () => {
    const png = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      Buffer.alloc(20),
    ]);
    expect(checkFileIntegrity("attachments/2025/img.png", png)).toEqual({ ok: true });
  });
});
