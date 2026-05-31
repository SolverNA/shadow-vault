/**
 * Чистые утилиты для путей хранилища. Единственный источник правды —
 * чтобы не дублировать одну и ту же логику в shadow-vault-manager/adapter-patcher.
 *
 * MOBILE-SAFE: без top-level node-импортов.
 */

/**
 * true если путь нужно пропускать (отдавать оригинальному адаптеру без
 * шифрования/подмены): корень хранилища и каталог конфигурации Obsidian
 * (.obsidian и всё внутри него).
 *
 * @param normalizedPath нормализованный путь относительно корня vault
 *                       ("" — корень).
 * @param configDir      имя каталога конфигурации (обычно ".obsidian").
 */
export function isBypassPath(normalizedPath: string, configDir: string): boolean {
  return (
    normalizedPath === "" ||
    normalizedPath === configDir ||
    normalizedPath.startsWith(configDir + "/")
  );
}
