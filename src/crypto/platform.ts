/**
 * Определение платформы и ленивый доступ к Node-модулям.
 *
 * КРИТИЧНО: node:crypto / fs / os / path НЕ импортируются на верхнем уровне —
 * на мобильных Obsidian require("crypto") бросит исключение при загрузке бандла.
 * Доступ только через ленивые геттеры внутри desktop-ветки за runtime-гейтом.
 */

/**
 * true, если доступен Node.js runtime (десктоп Obsidian / Electron / Node тесты).
 *
 * Не зависит от obsidian API напрямую (чтобы модуль тестировался в Node),
 * но если obsidian Platform доступен — он имеет приоритет (см. main.ts isDesktop).
 */
export function isNodeRuntime(): boolean {
  return (
    typeof process !== "undefined" &&
    !!process.versions &&
    !!process.versions.node
  );
}

/** Ленивый require Node-модуля (crypto/fs/os/path) за runtime-гейтом. */
export function nodeRequire<T = unknown>(moduleName: string): T {
  if (!isNodeRuntime()) {
    throw new Error(
      `[crypto] nodeRequire("${moduleName}") вызван вне Node runtime (mobile?)`
    );
  }
  // Доступ к require только внутри Node-ветки (гейт isNodeRuntime выше).
  // На mobile эта функция не вызывается, поэтому ссылка на require безопасна.
  // Берём require из доступных источников, не вычисляя его на верхнем уровне.
  const g = globalThis as unknown as { require?: NodeRequire };
  const req: NodeRequire | undefined =
    (typeof require !== "undefined" ? (require as NodeRequire) : undefined) ??
    (typeof module !== "undefined" && module.require
      ? (module.require.bind(module) as NodeRequire)
      : undefined) ??
    g.require;
  if (!req) {
    throw new Error(`[crypto] require недоступен для модуля "${moduleName}"`);
  }
  return req(moduleName) as T;
}

/** Доступ к WebCrypto SubtleCrypto на любой платформе (Node 16+ и браузер). */
export function getSubtle(): SubtleCrypto {
  const g = globalThis as unknown as { crypto?: Crypto };
  if (g.crypto && g.crypto.subtle) return g.crypto.subtle;
  // Node без globalThis.crypto (старые версии) — берём webcrypto из node:crypto
  if (isNodeRuntime()) {
    const nodeCrypto = nodeRequire<typeof import("crypto")>("crypto");
    const wc = (nodeCrypto as unknown as { webcrypto?: Crypto }).webcrypto;
    if (wc && wc.subtle) return wc.subtle;
  }
  throw new Error("[crypto] SubtleCrypto недоступен в данной среде");
}

/** Криптографически стойкие случайные байты на любой платформе. */
export function randomBytes(length: number): Uint8Array {
  const g = globalThis as unknown as { crypto?: Crypto };
  if (g.crypto && g.crypto.getRandomValues) {
    return g.crypto.getRandomValues(new Uint8Array(length));
  }
  if (isNodeRuntime()) {
    const nodeCrypto = nodeRequire<typeof import("crypto")>("crypto");
    return new Uint8Array(nodeCrypto.randomBytes(length));
  }
  throw new Error("[crypto] Источник случайности недоступен");
}
