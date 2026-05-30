/**
 * Тесты ленивого доступа к node-модулям (node-fs).
 *
 * Главная гарантия для mobile: модуль node-fs НЕ выполняет require("fs"|...)
 * при загрузке — только при первом вызове аксессора за runtime-гейтом.
 * В Node-окружении (jest) аксессоры должны возвращать реальные модули.
 */

import { describe, it, expect } from "@jest/globals";
import { nfs, nfsp, npath, nos, ncrypto, isNodeRuntime } from "../src/node-fs";

describe("node-fs ленивые аксессоры", () => {
  it("isNodeRuntime() в jest = true", () => {
    expect(isNodeRuntime()).toBe(true);
  });

  it("nfs() возвращает рабочий fs", () => {
    expect(typeof nfs().readdirSync).toBe("function");
  });

  it("nfsp() возвращает рабочий fs/promises", () => {
    expect(typeof nfsp().readFile).toBe("function");
  });

  it("npath() возвращает рабочий path", () => {
    expect(npath().join("a", "b")).toBe(["a", "b"].join(npath().sep));
  });

  it("nos() возвращает рабочий os", () => {
    expect(typeof nos().tmpdir()).toBe("string");
  });

  it("ncrypto() возвращает рабочий crypto", () => {
    expect(typeof ncrypto().randomBytes).toBe("function");
  });

  it("повторные вызовы кэшируют один и тот же модуль", () => {
    expect(nfsp()).toBe(nfsp());
    expect(npath()).toBe(npath());
  });
});
