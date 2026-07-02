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

/**
 * true если путь указывает на корень хранилища: "" (каноничный вид),
 * а также варианты нормализации "/" и ".".
 *
 * НЮАНС: корень входит в bypass (см. isBypassPath) — операции над самим
 * корнем (stat/exists/mkdir) должны идти в оригинальный адаптер. Но для
 * list() корень bypass'ить НЕЛЬЗЯ: иначе Obsidian увидит сырые .enc-имена
 * и построит индекс по неверным именам. list-патчи обязаны проверять
 * isVaultRoot ДО isBypassPath (см. AdapterPatcher.patchedList и
 * ShadowVaultManager.patchedList).
 */
export function isVaultRoot(normalizedPath: string): boolean {
  return normalizedPath === "" || normalizedPath === "/" || normalizedPath === ".";
}
