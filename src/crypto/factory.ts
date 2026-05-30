/**
 * Фабрика криптодвижка: выбирает реализацию по платформе.
 *
 * - Node runtime (десктоп Obsidian / Electron / тесты) → NodeCryptoEngine.
 * - Иначе (mobile / браузер)                            → WebCryptoEngine.
 *
 * Вызывающий код может переопределить выбор флагом forceWeb (например, на
 * десктопе для отладки кроссплатформенности).
 */

import { NodeCryptoEngine } from "../crypto-engine";
import { WebCryptoEngine } from "../web-crypto-engine";
import { isNodeRuntime } from "./platform";

export type AnyCryptoEngine = NodeCryptoEngine | WebCryptoEngine;

export function createCryptoEngine(opts?: { forceWeb?: boolean }): AnyCryptoEngine {
  if (opts?.forceWeb) return new WebCryptoEngine();
  return isNodeRuntime() ? new NodeCryptoEngine() : new WebCryptoEngine();
}
