#!/usr/bin/env node
/**
 * Собирает готовый к копированию каталог build/shadow-vault/.
 * Внутри: main.js, manifest.json, styles.css — всё что нужно Obsidian'у.
 *
 * Использование:
 *   node scripts/package-plugin.mjs
 *
 * Запускается также через `npm run build:plugin` (см. package.json).
 * Папка build/ в .gitignore — не коммитится.
 */

import * as fs from "fs/promises";
import * as nodePath from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = nodePath.dirname(__filename);
const root       = nodePath.resolve(__dirname, "..");
const outDir     = nodePath.join(root, "build", "shadow-vault");

const REQUIRED = ["main.js", "manifest.json", "styles.css"];

async function main() {
  // Чистим предыдущий build, чтобы не остались артефакты от старых билдов
  await fs.rm(nodePath.join(root, "build"), { recursive: true, force: true });
  await fs.mkdir(outDir, { recursive: true });

  for (const name of REQUIRED) {
    const src = nodePath.join(root, name);
    const dst = nodePath.join(outDir, name);
    try {
      await fs.copyFile(src, dst);
      const stat = await fs.stat(dst);
      console.log(`  ✓ ${name.padEnd(16)} (${formatSize(stat.size)})`);
    } catch (err) {
      console.error(`  ✗ ${name}: ${err.message}`);
      console.error(`    Запусти 'npm run build' перед package-plugin.`);
      process.exit(1);
    }
  }

  // Читаем manifest для красивого вывода версии
  const manifest = JSON.parse(await fs.readFile(nodePath.join(outDir, "manifest.json"), "utf8"));
  console.log("");
  console.log(`📦 ${manifest.name} v${manifest.version} → ${nodePath.relative(root, outDir)}/`);
  console.log("");
  console.log("Скопируй папку shadow-vault/ в:");
  console.log("  <твой-vault>/.obsidian/plugins/");
  console.log("");
  console.log("Затем в Obsidian: Settings → Community plugins → enable Shadow Vault.");
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(2) + " MB";
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
