/**
 * Виртуальный shadow manager для кросс-платформенной работы
 * Хранит расшифрованные файлы в памяти вместо отдельной директории на диске
 */

import { WebCryptoEngine } from "./web-crypto-engine";
import { PlatformAdapter } from "./platform-adapter";
import { detectFormat, plaintextSizeFromContainer } from "./crypto/format";
import { migrateBuffer, probeLegacyPassword } from "./crypto/migration";
import type { LegacyVariant } from "./crypto/legacy";
import type { Logger } from "./logger";
import type { PlainExportResult } from "./types";

export class VirtualShadowManager {
  private cache: Map<string, ArrayBuffer> = new Map();
  /**
   * Per-path очереди дисковых мутаций (write/remove/rename/copy) — аналог
   * encryptLocks в desktop ShadowVaultManager. Без сериализации медленный
   * старый encrypt мог завершить writeBinary ПОСЛЕ быстрого нового: на диске
   * старая версия, в кэше новая — рассинхрон до перезапуска.
   * Записи чистятся по завершении хвоста очереди — Map не растёт бесконечно.
   */
  private writeLocks: Map<string, Promise<unknown>> = new Map();

  /**
   * true пока идёт exportToPlaintext (отключение шифрования на mobile):
   * дисковая часть write() откладывается (кэш обновляется как обычно).
   * Без гейта правка файла ПОСЛЕ его экспорта писала бы свежий .enc, который
   * фаза 2 экспорта тут же удаляла — правка терялась. После УСПЕШНОГО
   * экспорта гейт НЕ снимается: вызывающий (main.disableEncryption) сразу
   * снимает патч адаптера, и поздние записи не должны воскрешать .enc.
   */
  private exportInProgress = false;

  /**
   * Пути, чьи дисковые записи отложены гейтом exportInProgress (актуальный
   * plaintext уже в кэше). При успехе экспорта дописываются PLAINTEXT'ом
   * (фаза 1.5), при провале — шифруются обратно в .enc.
   */
  private deferredDuringExport: Set<string> = new Set();

  private engine: WebCryptoEngine;
  private adapter: PlatformAdapter;
  /** Опциональный структурный логгер (DI из main); тесты передают undefined. */
  private logger?: Logger;

  constructor(engine: WebCryptoEngine, adapter: PlatformAdapter, logger?: Logger) {
    this.engine = engine;
    this.adapter = adapter;
    this.logger = logger;
  }

  /**
   * Читает файл (расшифровывает из .enc или берёт из кэша)
   * @param normalizedPath - путь к файлу (без .enc)
   * @returns расшифрованные данные
   */
  async read(normalizedPath: string): Promise<ArrayBuffer> {
    // 1. Проверяем кэш — возвращаем КОПИЮ, чтобы мутация потребителем не
    //    портила кэшированный буфер (рассинхрон с .enc).
    if (this.cache.has(normalizedPath)) {
      return this.cache.get(normalizedPath)!.slice(0);
    }

    // 2. Читаем .enc из хранилища
    const encPath = normalizedPath + ".enc";
    const encrypted = await this.adapter.readBinary(encPath);

    // 3. Расшифровываем
    const decrypted = await this.engine.decryptBuffer(encrypted);

    // 4. Кэшируем (свой экземпляр) и отдаём отдельную КОПИЮ наружу.
    this.cache.set(normalizedPath, decrypted);

    return decrypted.slice(0);
  }

  /**
   * Сериализует дисковую операцию по указанным путям: op стартует только
   * после завершения (успешного ИЛИ упавшего) всех ранее поставленных
   * операций на этих путях. Несколько путей нужны rename/copy — очередь
   * захватывается на оба пути атомарно (без вложенных захватов → без
   * взаимных блокировок при встречных rename).
   */
  private enqueue<T>(paths: string[], op: () => Promise<T>): Promise<T> {
    const prev = paths.map((p) => this.writeLocks.get(p) ?? Promise.resolve());
    // allSettled: упавшая предыдущая операция не «отравляет» очередь.
    const next = Promise.allSettled(prev).then(op);
    for (const p of paths) this.writeLocks.set(p, next);
    return next.finally(() => {
      // Удаляем себя из карты, только если после нас никто не встал в очередь.
      for (const p of paths) {
        if (this.writeLocks.get(p) === next) this.writeLocks.delete(p);
      }
    });
  }

  /**
   * Записывает файл (сохраняет в кэш и шифрует в .enc).
   *
   * Семантика кэша — optimistic: кэш обновляется СРАЗУ (до дисковой записи),
   * потому что Obsidian читает файл обратно немедленно после write
   * (read-after-write в редакторе) и ждать encrypt+writeBinary нельзя.
   * Компромисс: при ОШИБКЕ дисковой записи кэш инвалидируется, иначе read
   * отдавал бы «фантом» — данные, которых нет на диске (исчезли бы после
   * lock/перезапуска). Ошибка пробрасывается вызывающему.
   *
   * @param normalizedPath - путь к файлу (без .enc)
   * @param data - данные для записи
   */
  async write(normalizedPath: string, data: ArrayBuffer): Promise<void> {
    // Снимок данных на момент вызова: последующая мутация переданного буфера
    // потребителем не испортит ни кэш, ни шифруемое содержимое.
    const snapshot = data.slice(0);

    // Optimistic-кэш: обновляем сразу, до постановки в очередь на диск.
    this.cache.set(normalizedPath, snapshot);

    // Гейт экспорта (отключение шифрования): дисковую запись .enc откладываем —
    // фаза 2 экспорта удаляет .enc, и свежая запись потерялась бы. Актуальные
    // данные уже в кэше; exportToPlaintext допишет их plaintext'ом (фаза 1.5)
    // либо, при провале экспорта, зашифрует обратно в .enc.
    if (this.exportInProgress) {
      this.deferredDuringExport.add(normalizedPath);
      return;
    }

    // Дисковая часть сериализована per-path: параллельные записи одного пути
    // ложатся на диск строго в порядке вызова write.
    await this.enqueue([normalizedPath], async () => {
      try {
        const encrypted = await this.engine.encryptBuffer(snapshot);
        await this.adapter.writeBinary(normalizedPath + ".enc", encrypted);
      } catch (err) {
        // Откат кэша ТОЛЬКО если там всё ещё наш снимок: более поздний write
        // уже заменил значение — его судьба решится в его звене очереди.
        // Инвалидация (а не восстановление прежнего значения) безопаснее:
        // следующий read пойдёт на диск и вернёт истину (.enc или ENOENT).
        if (this.cache.get(normalizedPath) === snapshot) {
          this.cache.delete(normalizedPath);
        }
        this.logger?.error("vshadow", `запись .enc не удалась: ${normalizedPath}`, {
          path: normalizedPath,
          error: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    });
  }

  /**
   * Проверяет существование файла
   * @param normalizedPath - путь к файлу (без .enc)
   */
  async exists(normalizedPath: string): Promise<boolean> {
    // Проверяем кэш или .enc файл
    if (this.cache.has(normalizedPath)) {
      return true;
    }
    const encPath = normalizedPath + ".enc";
    return await this.adapter.exists(encPath);
  }

  /**
   * Удаляет файл
   * @param normalizedPath - путь к файлу (без .enc)
   */
  async remove(normalizedPath: string): Promise<void> {
    // В одной очереди с write: remove не должен обогнать «висящую» запись
    // этого же пути (иначе writeBinary воскресил бы .enc после удаления).
    await this.enqueue([normalizedPath], async () => {
      // Удаляем из кэша
      this.cache.delete(normalizedPath);

      // Удаляем .enc файл
      const encPath = normalizedPath + ".enc";
      await this.adapter.remove(encPath);
    });
  }

  /**
   * Переименовывает файл
   * @param oldPath - старый путь (без .enc)
   * @param newPath - новый путь (без .enc)
   */
  async rename(oldPath: string, newPath: string): Promise<void> {
    // Очередь на ОБА пути: rename не должен обогнать «висящую» запись
    // старого пути (перенёс бы недописанный .enc) и не должен быть затёрт
    // отставшей записью нового пути.
    await this.enqueue([oldPath, newPath], async () => {
      const oldEncPath = oldPath + ".enc";
      const newEncPath = newPath + ".enc";

      // Приоритет — нативный rename адаптера: атомарно, без пере-шифровки
      // (шифртекст не зависит от имени файла). Fallback read → write → remove
      // неатомарен: сбой между write и remove оставляет дубликат .enc.
      if (this.adapter.rename) {
        await this.adapter.rename(oldEncPath, newEncPath);
      } else {
        const encrypted = await this.adapter.readBinary(oldEncPath);
        await this.adapter.writeBinary(newEncPath, encrypted);
        await this.adapter.remove(oldEncPath);
      }

      // Кэш переносим ПОСЛЕ успешной дисковой операции: если rename упал,
      // старая запись кэша остаётся валидной.
      if (this.cache.has(oldPath)) {
        const data = this.cache.get(oldPath)!;
        this.cache.delete(oldPath);
        this.cache.set(newPath, data);
      }
    });
  }

  /**
   * Копирует файл
   * @param srcPath - исходный путь (без .enc)
   * @param dstPath - целевой путь (без .enc)
   */
  async copy(srcPath: string, dstPath: string): Promise<void> {
    // Очередь на оба пути: не читаем src, пока его запись «в полёте», и не
    // даём отставшей записи dst затереть результат копии.
    await this.enqueue([srcPath, dstPath], async () => {
      // Копируем .enc файл
      const srcEncPath = srcPath + ".enc";
      const dstEncPath = dstPath + ".enc";

      const encrypted = await this.adapter.readBinary(srcEncPath);
      await this.adapter.writeBinary(dstEncPath, encrypted);

      // Кэш-копию создаём ПОСЛЕ успешной дисковой копии: при сбое кэш dst
      // не содержит фантома, которого нет на диске.
      if (this.cache.has(srcPath)) {
        this.cache.set(dstPath, this.cache.get(srcPath)!.slice(0));
      }
    });
  }

  /**
   * Получает статистику файла
   * @param normalizedPath - путь к файлу (без .enc)
   */
  async stat(normalizedPath: string): Promise<{ size: number; mtime: number } | null> {
    const encPath = normalizedPath + ".enc";
    const s = await this.adapter.stat(encPath);
    if (!s) return null;

    // Размер plaintext, а не .enc. Если файл в кэше — точный размер из кэша.
    if (this.cache.has(normalizedPath)) {
      return { size: this.cache.get(normalizedPath)!.byteLength, mtime: s.mtime };
    }

    // Иначе оцениваем по содержимому .enc без расшифровки (для chunked — по
    // префиксам длин сегментов). Mobile-адаптер читает файл целиком, но для
    // согласованности размера это допустимо (файлы обычно небольшие).
    try {
      const buf = new Uint8Array(await this.adapter.readBinary(encPath));
      return { size: plaintextSizeFromContainer(buf), mtime: s.mtime };
    } catch {
      // Не удалось прочитать .enc — отдаём сырой размер (лучше, чем ничего).
      return { size: s.size, mtime: s.mtime };
    }
  }

  /**
   * Список файлов в директории
   * @param dirPath - путь к директории
   * @returns список файлов и папок (без .enc расширений)
   */
  async list(dirPath: string): Promise<{ files: string[]; folders: string[] }> {
    const result = await this.adapter.list(dirPath);

    // Убираем .enc расширения из файлов
    const files = result.files
      .filter(f => f.endsWith(".enc"))
      .map(f => f.slice(0, -4)); // убираем ".enc"

    return { files, folders: result.folders };
  }

  /**
   * Очищает кэш (при блокировке vault)
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Инвалидирует кэш по пути: сам путь и всё под ним (prefix + "/").
   * Нужен при папочных операциях (rmdir/rename/trash папки), которые идут
   * мимо VSM через оригинальный адаптер: без инвалидации кэш «воскрешал» бы
   * удалённые/переехавшие файлы (exists → true, read → старые данные).
   */
  invalidatePrefix(prefix: string): void {
    for (const key of [...this.cache.keys()]) {
      if (key === prefix || key.startsWith(prefix + "/")) {
        this.cache.delete(key);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ФАЗА 4: миграция legacy → v2 (mobile, последовательно через Vault API)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Рекурсивно собирает все .enc файлы хранилища (полные пути с .enc).
   * Папка configDir (.obsidian) пропускается — там нет наших шифрованных заметок.
   */
  private async scanEncFiles(configDir: string): Promise<string[]> {
    const out: string[] = [];
    const walk = async (dir: string): Promise<void> => {
      const { files, folders } = await this.adapter.list(dir);
      for (const f of files) {
        if (f.endsWith(".enc")) out.push(f);
      }
      for (const sub of folders) {
        const name = sub.split("/").pop() ?? "";
        if (name.startsWith(".") || name === configDir) continue;
        await walk(sub);
      }
    };
    await walk("");
    return out;
  }

  /**
   * Проверяет, есть ли в хранилище хотя бы один legacy .enc (не v2 по MAGIC).
   */
  async hasLegacyFiles(configDir: string): Promise<boolean> {
    const enc = await this.scanEncFiles(configDir);
    for (const p of enc) {
      try {
        const buf = new Uint8Array(await this.adapter.readBinary(p));
        // Legacy — ТОЛЬКО позитивно. v2/v2-chunked и пустые/битые (unknown) — нет.
        const fmt = detectFormat(buf);
        if (fmt === "legacy-node" || fmt === "legacy-web") return true;
      } catch {
        // нечитаемый файл — пропускаем
      }
    }
    return false;
  }

  /**
   * Проверяет пароль через trial-decrypt первого LEGACY .enc (для хранилищ
   * без verificationBlob). Возвращает:
   *   - "LEGACY_OK"             — нашёлся legacy-файл и пароль к нему подошёл;
   *   - "LEGACY_WRONG_PASSWORD" — нашёлся legacy-файл, но пароль не подошёл;
   *   - "NOT_LEGACY"            — legacy-файлов нет (всё v2/пусто) → проверять нечего.
   * Пустые (0 байт) и v2/v2-chunked файлы пропускаются — не legacy.
   */
  async probePassword(
    configDir: string,
    password: string
  ): Promise<"NOT_LEGACY" | "LEGACY_OK" | "LEGACY_WRONG_PASSWORD"> {
    const enc = await this.scanEncFiles(configDir);
    for (const p of enc) {
      try {
        const buf = new Uint8Array(await this.adapter.readBinary(p));
        const fmt = detectFormat(buf);
        if (fmt !== "legacy-node" && fmt !== "legacy-web") continue;
        const res = await probeLegacyPassword(buf, password);
        // probe для legacy-образца вернёт LEGACY_OK или LEGACY_WRONG_PASSWORD.
        return res.status === "LEGACY_OK" ? "LEGACY_OK" : "LEGACY_WRONG_PASSWORD";
      } catch {
        // продолжаем к следующему
      }
    }
    return "NOT_LEGACY"; // legacy-файлов нет
  }

  /**
   * Самовосстановление блоба для v2-хранилища без verificationBlob (mobile).
   * Пытается расшифровать первый ВАЛИДНЫЙ v2/v2-chunked .enc текущим движком
   * (ключ уже выведен из email+password). Успех → пароль верный. Провал
   * (GCM auth) → неверный пароль. Если валидных v2-файлов нет — null
   * (пустое/новое хранилище, проверять нечего).
   *
   * @returns true — пароль верный; false — неверный; null — нет v2-файлов.
   */
  async validateV2Password(configDir: string): Promise<boolean | null> {
    const enc = await this.scanEncFiles(configDir);
    for (const p of enc) {
      try {
        const buf = new Uint8Array(await this.adapter.readBinary(p));
        const fmt = detectFormat(buf);
        if (fmt !== "v2" && fmt !== "v2-chunked") continue; // пропускаем пустые/legacy/битые
        try {
          await this.engine.decryptBuffer(buf);
          return true; // расшифровалось текущим ключом → пароль верный
        } catch {
          return false; // GCM auth fail → неверный пароль
        }
      } catch {
        // нечитаемый файл — к следующему
      }
    }
    return null; // валидных v2-файлов нет
  }

  /**
   * Мигрирует все legacy .enc → v2 последовательно (mobile через Vault API).
   *
   * Пофайлово: read → migrateBuffer (legacy-decrypt + re-encrypt v2 +
   * round-trip verify) → writeBinary поверх того же .enc. На mobile нет
   * fs.rename, поэтому writeBinary — это запись через Obsidian adapter (он
   * сам пишет атомарно на уровне ОС). v2 пишется только ПОСЛЕ успешного
   * round-trip verify, поэтому окно потери данных минимально.
   * Идемпотентность: уже-v2 файлы пропускаются (skipped-v2).
   */
  /**
   * Пере-шифровывает все .enc новым ключом (смена пароля/email на mobile).
   *
   * Пофайлово: read(.enc) → decrypt СТАРЫМ движком (this.engine) → encrypt
   * НОВЫМ движком → round-trip verify (decrypt новым движком, сравнение байт)
   * → writeBinary поверх .enc. Новый шифртекст пишется ТОЛЬКО после успешного
   * round-trip verify в памяти, поэтому окно повреждения данных на каждый файл
   * минимально (одна атомарная writeBinary через Obsidian adapter).
   *
   * НЮАНС mobile: настоящей кросс-файловой атомарности (как rename .new→.enc на
   * desktop) нет. Если процесс упадёт в середине, часть файлов будет под новым
   * ключом, часть под старым. Для восстановления см. main.changeCredentials:
   * verificationBlob обновляется только после полного успеха, а смешанное
   * состояние читаемо, т.к. оба ключа известны во время прогона (повторный
   * запуск с новым паролем дочитает остаток — будущая доработка).
   *
   * После успеха движок чтения переключается на новый ключ и кэш очищается.
   *
   * @param newEngine движок с уже загруженным НОВЫМ ключом
   */
  async reEncryptAll(
    configDir: string,
    newEngine: WebCryptoEngine,
    onProgress?: (done: number, total: number) => void
  ): Promise<void> {
    const encFiles = await this.scanEncFiles(configDir);
    const total = encFiles.length;

    for (let i = 0; i < total; i++) {
      const encPath = encFiles[i];
      const buf = new Uint8Array(await this.adapter.readBinary(encPath));
      if (buf.length === 0) {
        // Legacy 0-байтный .enc → пустой plaintext. Пере-шифруем в ВАЛИДНЫЙ
        // v2-контейнер новым ключом (единый контракт пустых файлов), а не
        // оставляем 0 байт.
        const reencEmpty = await newEngine.encryptBuffer(new Uint8Array(0));
        await this.adapter.writeBinary(encPath, reencEmpty);
        this.cache.delete(encPath.slice(0, -4));
        onProgress?.(i + 1, total);
        continue;
      }
      // Расшифровываем старым ключом
      const plain = await this.engine.decryptBuffer(buf);
      // Шифруем новым
      const reenc = await newEngine.encryptBuffer(plain);
      // Round-trip verify: новый шифртекст обязан расшифроваться в исходник
      const check = new Uint8Array(await newEngine.decryptBuffer(reenc));
      const orig = new Uint8Array(plain);
      if (check.length !== orig.length) {
        throw new Error(`[VirtualShadow] round-trip verify не прошёл (длина): ${encPath}`);
      }
      for (let k = 0; k < check.length; k++) {
        if (check[k] !== orig[k]) {
          throw new Error(`[VirtualShadow] round-trip verify не прошёл (байты): ${encPath}`);
        }
      }
      await this.adapter.writeBinary(encPath, reenc);
      this.cache.delete(encPath.slice(0, -4));
      onProgress?.(i + 1, total);
    }

    // Переключаем движок чтения на новый ключ и чистим кэш.
    this.engine = newEngine;
    this.cache.clear();
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Экспорт plaintext (отключение шифрования на mobile)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Экспортирует все .enc хранилища в plaintext и удаляет .enc — mobile-аналог
   * desktop ShadowVaultManager.exportShadowToOriginal (тот же контракт
   * PlainExportResult и та же двухфазная схема):
   *
   *   ФАЗА 1 — для каждого .enc: расшифровать (кэш приоритетнее — там самая
   *     свежая версия), записать plaintext через ОРИГИНАЛЬНЫЙ адаптер,
   *     верифицировать read-back'ом. .enc НЕ трогаются. Нерасшифрованные
   *     (повреждены/чужой ключ) → skippedOrphans, их .enc остаются на диске
   *     как единственная копия данных. Ошибка записи/verify → failed.
   *   ФАЗА 1.5 — дописать правки, отложенные гейтом write-through (из кэша).
   *   ФАЗА 2 — только если failed пуст: удалить .enc СТРОГО экспортированных.
   *
   * ГЕЙТ WRITE-THROUGH: на время экспорта дисковая часть write() откладывается
   * (см. exportInProgress). При успехе гейт остаётся взведённым — вызывающий
   * немедленно снимает патч адаптера (записи пойдут plaintext'ом нативно),
   * при провале гейт снимается и отложенное шифруется обратно в .enc.
   */
  async exportToPlaintext(
    configDir: string,
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<PlainExportResult> {
    this.exportInProgress = true;
    let success = false;
    try {
      const result = await this.exportToPlaintextInner(configDir, onProgress);
      success = result.failed.length === 0;
      return result;
    } finally {
      if (!success) {
        // Экспорт не удался — шифрование остаётся включённым: снимаем гейт
        // и дошифровываем отложенные записи обратно в .enc.
        this.exportInProgress = false;
        await this.flushDeferredAfterExport();
      }
    }
  }

  private async exportToPlaintextInner(
    configDir: string,
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<PlainExportResult> {
    const exported: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];
    const skippedOrphans: string[] = [];

    // Дожидаемся дисковых записей, начатых ДО гейта: поздний writeBinary не
    // должен воскресить .enc после его удаления в фазе 2.
    await Promise.allSettled([...this.writeLocks.values()]);

    const encFiles = await this.scanEncFiles(configDir);
    const total = encFiles.length;
    this.logger?.info("vshadow", "export → plaintext (фаза 1: расшифровка+verify)", { files: total });

    // ── ФАЗА 1: расшифровываем и пишем plaintext, .enc не трогаем ──
    for (let i = 0; i < total; i++) {
      const encPath = encFiles[i];
      const plainPath = encPath.slice(0, -".enc".length);
      try {
        let plain: ArrayBuffer;
        if (this.cache.has(plainPath)) {
          // Кэш — самая свежая версия (optimistic write мог ещё не долететь).
          plain = this.cache.get(plainPath)!.slice(0);
        } else {
          const encrypted = await this.adapter.readBinary(encPath);
          try {
            plain = await this.engine.decryptBuffer(encrypted);
          } catch {
            // Не расшифровался (повреждён или чужой ключ) → orphan: .enc —
            // единственная копия данных, НЕ удаляем и не считаем ошибкой.
            skippedOrphans.push(plainPath);
            onProgress?.(i + 1, total, plainPath);
            continue;
          }
        }
        await this.exportOnePlain(plainPath, plain);
        exported.push(plainPath);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger?.error("vshadow", `export файла не удался: ${plainPath}`, {
          path: plainPath,
          error: msg,
        });
        failed.push({ path: plainPath, error: msg });
      }
      onProgress?.(i + 1, total, plainPath);
    }

    if (failed.length > 0) {
      this.logger?.error("vshadow", "export: часть файлов не удалась — .enc НЕ удаляем", {
        failed: failed.length,
      });
      return { exported, failed, skippedOrphans };
    }

    if (skippedOrphans.length > 0) {
      this.logger?.warn("vshadow", "export: orphan .enc оставлены на диске", {
        count: skippedOrphans.length,
        files: skippedOrphans,
      });
    }

    // ── ФАЗА 1.5: дописываем правки, отложенные гейтом (из кэша) ──
    // Несколько проходов: пока дописываем, могут прилететь новые записи.
    for (let pass = 0; pass < 10 && this.deferredDuringExport.size > 0; pass++) {
      const deferred = [...this.deferredDuringExport];
      this.deferredDuringExport.clear();
      this.logger?.debug("vshadow", "export фаза 1.5: дозапись отложенных правок", {
        pass,
        files: deferred.length,
      });
      for (const plainPath of deferred) {
        const data = this.cache.get(plainPath);
        if (!data) continue; // удалён после записи — дописывать нечего
        try {
          await this.exportOnePlain(plainPath, data.slice(0));
          if (!exported.includes(plainPath)) exported.push(plainPath);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          this.logger?.error("vshadow", `export отложенной правки не удался: ${plainPath}`, {
            path: plainPath,
            error: msg,
          });
          failed.push({ path: plainPath, error: msg });
        }
      }
      if (failed.length > 0) {
        return { exported, failed, skippedOrphans };
      }
    }

    // ── ФАЗА 2: удаляем .enc СТРОГО экспортированных файлов ──
    this.logger?.info("vshadow", "export фаза 2: удаление .enc", { exported: exported.length });
    for (const plainPath of exported) {
      try {
        await this.adapter.remove(plainPath + ".enc");
      } catch (err) {
        // Plaintext уже на месте и проверен — данные не потеряны. Логируем;
        // повторное отключение шифрования до-удалит остатки.
        this.logger?.error("vshadow", `export: не удалось удалить .enc: ${plainPath}`, {
          path: plainPath,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    this.logger?.info("vshadow", "export завершён", {
      files: exported.length,
      errors: failed.length,
      skippedOrphans: skippedOrphans.length,
    });
    return { exported, failed, skippedOrphans };
  }

  /**
   * Записывает plaintext через оригинальный адаптер и верифицирует read-back'ом
   * (побайтовая сверка) — .enc удаляется в фазе 2 только после такой проверки.
   */
  private async exportOnePlain(plainPath: string, plain: ArrayBuffer): Promise<void> {
    await this.adapter.writeBinary(plainPath, plain);
    const check = new Uint8Array(await this.adapter.readBinary(plainPath));
    const orig = new Uint8Array(plain);
    if (check.length !== orig.length) {
      throw new Error("verify не прошёл: длина записанного plaintext не совпала");
    }
    for (let k = 0; k < check.length; k++) {
      if (check[k] !== orig[k]) {
        throw new Error("verify не прошёл: записанный plaintext не совпал");
      }
    }
  }

  /**
   * Шифрует отложенные гейтом записи обратно в .enc — только при НЕУДАЧНОМ
   * экспорте (шифрование остаётся включённым, правки нельзя терять).
   */
  private async flushDeferredAfterExport(): Promise<void> {
    for (let pass = 0; pass < 10 && this.deferredDuringExport.size > 0; pass++) {
      const paths = [...this.deferredDuringExport];
      this.deferredDuringExport.clear();
      for (const p of paths) {
        const data = this.cache.get(p);
        if (!data) continue;
        try {
          await this.write(p, data.slice(0)); // гейт уже снят → обычный путь в .enc
        } catch (err) {
          this.logger?.error("vshadow", `дошифровка отложенной записи не удалась: ${p}`, {
            path: p,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }
  }

  async migrateLegacyToV2(
    configDir: string,
    password: string,
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<{ migrated: number; skipped: number; failed: Array<{ path: string; error: string }> }> {
    const encFiles = await this.scanEncFiles(configDir);
    let migrated = 0;
    let skipped = 0;
    let done = 0;
    const failed: Array<{ path: string; error: string }> = [];
    let hint: LegacyVariant | undefined;

    for (const encPath of encFiles) {
      try {
        const buf = new Uint8Array(await this.adapter.readBinary(encPath));
        const res = await migrateBuffer(buf, password, this.engine, hint);
        if (res.status === "skipped-v2") {
          skipped++;
        } else {
          hint = res.variant;
          const ab = res.v2.buffer.slice(
            res.v2.byteOffset,
            res.v2.byteOffset + res.v2.byteLength
          );
          await this.adapter.writeBinary(encPath, ab);
          // Сбрасываем кэш для этого файла — он мог содержать stale-данные.
          this.cache.delete(encPath.slice(0, -4));
          migrated++;
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger?.error("vshadow", `миграция файла не удалась: ${encPath}`, {
          path: encPath,
          error: msg,
        });
        failed.push({ path: encPath, error: msg });
      }
      done++;
      onProgress?.(done, encFiles.length, encPath);
    }

    return { migrated, skipped, failed };
  }
}
