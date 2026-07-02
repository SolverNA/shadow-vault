/**
 * Тесты чистых утилит путей (src/path-utils.ts).
 *
 * Покрытие:
 *   - isBypassPath: корень и configDir → bypass, обычные пути → нет
 *   - isVaultRoot: варианты нормализации корня ("", "/", ".")
 *     и контракт «list-патчи проверяют isVaultRoot ДО isBypassPath»
 */

import { describe, it, expect } from "@jest/globals";
import { isBypassPath, isVaultRoot } from "../src/path-utils";

const CONFIG = ".obsidian";

describe("isBypassPath", () => {
  it("корень ('') → bypass (операции над самим корнем идут в оригинал)", () => {
    expect(isBypassPath("", CONFIG)).toBe(true);
  });

  it("configDir и его содержимое → bypass", () => {
    expect(isBypassPath(".obsidian", CONFIG)).toBe(true);
    expect(isBypassPath(".obsidian/app.json", CONFIG)).toBe(true);
    expect(isBypassPath(".obsidian/plugins/my-plugin/data.json", CONFIG)).toBe(true);
  });

  it("обычные пути → НЕ bypass", () => {
    expect(isBypassPath("note.md", CONFIG)).toBe(false);
    expect(isBypassPath("Notes/MyNote.md", CONFIG)).toBe(false);
    // Похожее имя, но не configDir
    expect(isBypassPath(".obsidian-backup/x.md", CONFIG)).toBe(false);
  });

  it("уважает нестандартный configDir", () => {
    expect(isBypassPath(".config-custom", ".config-custom")).toBe(true);
    expect(isBypassPath(".obsidian", ".config-custom")).toBe(false);
  });
});

describe("isVaultRoot", () => {
  it("варианты корня ('', '/', '.') → true", () => {
    expect(isVaultRoot("")).toBe(true);
    expect(isVaultRoot("/")).toBe(true);
    expect(isVaultRoot(".")).toBe(true);
  });

  it("не-корневые пути → false", () => {
    expect(isVaultRoot("note.md")).toBe(false);
    expect(isVaultRoot(".obsidian")).toBe(false);
    expect(isVaultRoot("./sub")).toBe(false);
    expect(isVaultRoot("/abs")).toBe(false);
  });

  it("контракт list-патча: корень — root, но при этом bypass; служебные — bypass, но не root", () => {
    // Именно поэтому list-патчи проверяют isVaultRoot ДО isBypassPath:
    // корень транслируется, .obsidian/... остаётся в bypass.
    expect(isVaultRoot("") && isBypassPath("", CONFIG)).toBe(true);
    expect(isVaultRoot(".obsidian")).toBe(false);
    expect(isBypassPath(".obsidian", CONFIG)).toBe(true);
  });
});
