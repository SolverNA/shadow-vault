/**
 * SessionManager — управление жизненным циклом сессии ShadowVault.
 *
 * Гарантии безопасности:
 *   1. Теневое хранилище ВСЕГДА удаляется при корректном завершении.
 *   2. Ключ шифрования ВСЕГДА обнуляется при завершении сессии.
 *   3. Crash Recovery обнаруживает потерянные записи и восстанавливает их.
 *
 * Механизм обнаружения краша:
 *   - При старте создаётся файл .session_active в Оригинальном хранилище.
 *   - При корректном завершении файл удаляется.
 *   - Если при следующем запуске .session_active существует → предыдущая сессия упала.
 *
 * Механизм Crash Recovery (поиск потерянных записей):
 *   - Файл считается «потерянным», если shadow.mtime > original.mtime.
 *   - Это возможно только если write-through записал в shadow, но НЕ успел
 *     атомарно обновить original до краша.
 *   - Фоновые декрипты НЕ создают такого расхождения, потому что
 *     ensureDecrypted() копирует mtime оригинала в shadow (Шаг 3, utimes).
 */

import * as fsp from "fs/promises";
import * as fs from "fs";
import * as nodePath from "path";
import * as os from "os";
import { CryptoEngine } from "./crypto-engine";
import { legacyShadowRoot } from "./shadow-location";
import { MTIME_TOLERANCE_MS, atomicWrite, fileExists, isServiceEntryName } from "./fs-utils";
import { checkFileIntegrity, compareSemantic } from "./integrity-check";
import type { Logger } from "./logger";

/**
 * Имя файла-индикатора активной сессии.
 * Хранится в папке плагина (<vault>/.obsidian/plugins/shadow-vault/session.lock)
 * чтобы не засорять оригинальное хранилище и не попадать под Obsidian-индексацию.
 */
const SESSION_FILE = "session.lock";

/** Старый путь индикатора (до v1.1.0) — используется для миграции */
const LEGACY_SESSION_FILE = ".session_active";

/** JSON-структура session.lock */
interface SessionFileContent {
  startedAt: string;   // ISO-строка
  shadowRoot: string;  // абсолютный путь к теневому хранилищу
  pid?: number;        // PID процесса Obsidian — диагностика, не используется в логике
}

export interface CrashRecoveryResult {
  /** Пути файлов, которые были успешно перешифрованы (изменения из shadow → оригинал) */
  recoveredFiles: string[];
  /** Пути файлов, которые не удалось восстановить (ошибки шифрования/ФС/целостности) */
  failedFiles:    string[];
  /** Пути файлов, где shadow оказался повреждён (Этап 2) — данные оставлены в оригинале */
  corruptedShadow: string[];
}

export interface SessionStartResult {
  /** true если обнаружен краш предыдущей сессии */
  hadCrash: boolean;
  /** Результат восстановления (только при hadCrash=true) */
  recovery?: CrashRecoveryResult;
}

export class SessionManager {
  private readonly sessionFilePath: string;
  /** Старый путь — проверяется и удаляется при обнаружении (миграция) */
  private readonly legacySessionFilePath: string;

  /**
   * СТАРОЕ расположение shadow (до переноса в app-data): сиблинг хранилища.
   * После обновления плагина здесь может остаться recovery-shadow от
   * крашнувшейся сессии старой версии — startSession проверяет ОБА места,
   * чтобы не потерять несинхронизированные правки. Если резолвер работает
   * в fallback-режиме, legacyShadowPath совпадает с shadowRoot — тогда
   * отдельная legacy-обработка отключается (см. legacyShadowDiffers).
   */
  private readonly legacyShadowPath: string;

  /** Опциональный структурный логгер (DI из main); тесты передают undefined. */
  private readonly logger?: Logger;

  constructor(
    private readonly engine:       CryptoEngine,
    private readonly originalRoot: string,
    private readonly shadowRoot:   string,
    pluginDirAbs:                  string,
    logger?:                       Logger,
    /** Имя каталога конфигурации Obsidian — исключается из сканов shadow. */
    private readonly configDir:    string = ".obsidian"
  ) {
    this.sessionFilePath = nodePath.join(pluginDirAbs, SESSION_FILE);
    this.legacySessionFilePath = nodePath.join(originalRoot, LEGACY_SESSION_FILE);
    this.legacyShadowPath = legacyShadowRoot(originalRoot);
    this.logger = logger;
  }

  /** true если legacy-сиблинг — ОТДЕЛЬНОЕ от текущего shadow место. */
  private get legacyShadowDiffers(): boolean {
    return nodePath.normalize(this.legacyShadowPath) !== nodePath.normalize(this.shadowRoot);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Публичный API
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Вызывается при старте плагина после успешной деривации ключа.
   *
   * Алгоритм:
   *   1. Миграция: если старый .session_active есть в originalRoot, считаем
   *      это маркером краша и сразу удаляем (он больше там не нужен).
   *   2. Проверяем наличие session.lock в папке плагина. Дополнительно — наличие
   *      shadow vault: даже если lock потерялся, существование shadow с файлами
   *      означает что предыдущая сессия не завершилась корректно.
   *   3. Если краш обнаружен → recover.
   *   4. Создаём новый session.lock.
   */
  async startSession(): Promise<SessionStartResult> {
    let hadCrash = false;
    let recovery: CrashRecoveryResult | undefined;

    // ── Миграция: убираем старый .session_active из оригинала ──────────────
    if (await fileExists(this.legacySessionFilePath)) {
      hadCrash = true;
      this.logger?.warn("session", "найден legacy .session_active в оригинале — миграция и recovery");
      await fsp.unlink(this.legacySessionFilePath).catch(() => undefined);
    }

    // ── Текущий session.lock (в папке плагина) ─────────────────────────────
    if (await fileExists(this.sessionFilePath)) {
      hadCrash = true;
      this.logger?.warn("session", "session.lock существует — предыдущая сессия не завершилась");
    }

    // ── Дополнительный сигнал: shadow vault существует и не пуст ───────────
    // Если плагин крашнулся ДО создания lock'а (или lock удалён вручную),
    // присутствие shadow с файлами — однозначный признак незавершённой сессии.
    if (!hadCrash && (await this.shadowHasFiles())) {
      hadCrash = true;
      this.logger?.warn("session", "shadow vault не пуст — обнаружен краш без lock-файла");
    }

    // ── Legacy shadow (сиблинг vault'а, до переноса в app-data) ────────────
    // После обновления плагина recovery-shadow крашнувшейся СТАРОЙ версии
    // лежит в старом месте. Не проверить его — потерять несинхронизированные
    // правки пользователя (recoverFromCrash обработает оба места).
    if (!hadCrash && this.legacyShadowDiffers && (await this.shadowHasFilesIn(this.legacyShadowPath))) {
      hadCrash = true;
      this.logger?.warn("session", "найден непустой legacy shadow (сиблинг vault'а) — recovery из старого места", {
        legacyShadow: this.legacyShadowPath,
      });
    }

    if (hadCrash) {
      recovery = await this.recoverFromCrash();
      this.logger?.info("session", "recovery завершён", {
        ok: recovery.recoveredFiles.length,
        corrupted: recovery.corruptedShadow.length,
        failed: recovery.failedFiles.length,
      });
    }

    await this.createSessionFile();
    return { hadCrash, recovery };
  }

  /**
   * Синхронно уничтожает ключ. Используется в sync-cleanup при закрытии Obsidian,
   * когда async endSession не успевает завершиться.
   */
  destroyEngineSync(): void {
    this.engine.destroy();
  }

  /** true если в shadowRoot есть хотя бы один обычный файл (не считая .obsidian symlink) */
  private async shadowHasFiles(): Promise<boolean> {
    return this.shadowHasFilesIn(this.shadowRoot);
  }

  /** Та же проверка для произвольного корня (текущий shadow или legacy-сиблинг). */
  private async shadowHasFilesIn(rootAbs: string): Promise<boolean> {
    if (!(await fileExists(rootAbs))) return false;
    try {
      const entries = await fsp.readdir(rootAbs, { withFileTypes: true });
      for (const e of entries) {
        // Служебные артефакты не считаются данными. Пользовательские dot-пути
        // (.trash и т.п.) — считаются: их остаток в shadow означает краш,
        // и recovery должен зашифровать их обратно в оригинал.
        // .obsidian-symlink отсекается и по имени (configDir), и по типу
        // (Dirent симлинка — не file и не directory).
        if (isServiceEntryName(e.name, this.configDir)) continue;
        if (e.isFile() || e.isDirectory()) return true;
      }
    } catch { /* нет доступа — считаем что shadow пуст */ }
    return false;
  }

  /**
   * Корректное завершение сессии.
   *
   * Последовательность действий (порядок важен!):
   *   1. Удаляем Теневое хранилище рекурсивно (расшифрованные данные исчезают с диска).
   *   2. Удаляем .session_active (сигнал: завершение было корректным).
   *   3. Уничтожаем ключ шифрования в RAM (engine.destroy()).
   *
   * Если удаление теневого хранилища частично завершается с ошибкой
   * (например, файл заблокирован на Windows) — логируем, но не останавливаем.
   * .session_active удаляется ТОЛЬКО после успешного удаления shadow vault,
   * иначе следующий запуск не запустит recovery для оставшихся файлов.
   *
   * @param opts.keepShadowForRecovery — true если финальный encrypt-back не смог
   *   зашифровать часть файлов: shadow vault и session.lock НЕ удаляются, чтобы
   *   при следующем запуске сработал crash recovery (аналогично syncCleanup).
   *   Ключ шифрования уничтожается в любом случае.
   */
  async endSession(opts?: { keepShadowForRecovery?: boolean }): Promise<void> {
    if (opts?.keepShadowForRecovery) {
      this.logger?.warn(
        "session",
        "shadow vault и session.lock сохранены для recovery — encrypt-back завершился с ошибками"
      );
      this.engine.destroy();
      return;
    }

    let shadowDeleted = false;

    try {
      await this.deleteShadowVault();
      shadowDeleted = true;
    } catch (err) {
      this.logger?.error("session", "не удалось полностью удалить теневое хранилище", {
        error: err instanceof Error ? err.message : String(err),
      });
    }

    if (shadowDeleted) {
      // Только после успешного удаления shadow снимаем флаг сессии
      await this.removeSessionFile();
    } else {
      this.logger?.warn("session", "session.lock НЕ удалён — при следующем запуске будет recovery");
    }

    // Ключ обнуляется в любом случае
    this.engine.destroy();
  }

  /**
   * Crash Recovery: двухэтапная проверка целостности и восстановление потерянных записей.
   *
   * Алгоритм:
   *   Этап 0 (фильтр): берём только файлы, чей shadow строго новее оригинала
   *     (с допуском MTIME_TOLERANCE_MS на погрешность ФС).
   *   Этап 1 (semantic): расшифровываем оригинал и сравниваем побайтово с shadow.
   *     Идентичны → пропускаем (нет реальных изменений несмотря на mtime).
   *     Различаются → переходим к Этапу 2.
   *   Этап 2 (integrity): проверяем что shadow-файл не битый (UTF-8/magic bytes).
   *     OK → шифруем shadow → оригинал, восстанавливаем правку.
   *     Битый → оставляем оригинал, помечаем corruptedShadow, не теряем данные пользователя.
   *   Если оригинал отсутствует или повреждён (decrypt fails) — относимся как к
   *     "original-missing": доверяем shadow, если он прошёл Этап 2.
   *
   * После recovery shadow vault не удаляется — его чистит endSession().
   * startSession() вызывает recoverFromCrash() ДО создания нового .session_active.
   *
   * ДВА МЕСТА: recovery проходит и по ТЕКУЩЕМУ shadow (app-data), и по
   * legacy-сиблингу vault'а (recovery-shadow от версии плагина до переноса).
   * Порядок важен: сначала текущий shadow, потом legacy. Recovery пишет .enc
   * с mtime=now, поэтому у второго прохода mtime-фильтр (Этап 0) отсекает
   * его более СТАРЫЕ копии тех же файлов — побеждает правка из более новой
   * сессии (текущий shadow всегда новее legacy: legacy мог остаться только
   * от сессии ДО обновления плагина).
   *
   * После успешного legacy-recovery (без failed) legacy-каталог УДАЛЯЕТСЯ:
   * это plaintext в потенциально облачной папке — именно от него мы уходили.
   */
  async recoverFromCrash(): Promise<CrashRecoveryResult> {
    const result = await this.recoverFromShadowRoot(this.shadowRoot);

    if (this.legacyShadowDiffers && (await fileExists(this.legacyShadowPath))) {
      const legacy = await this.recoverFromShadowRoot(this.legacyShadowPath);
      result.recoveredFiles.push(...legacy.recoveredFiles);
      result.failedFiles.push(...legacy.failedFiles);
      result.corruptedShadow.push(...legacy.corruptedShadow);

      if (legacy.failedFiles.length === 0) {
        // Всё восстановлено (или было идентично) — plaintext-сиблинг больше
        // не нужен, убираем утечку из облачной папки.
        try {
          await fsp.rm(this.legacyShadowPath, { recursive: true, force: true });
          this.logger?.info("session", "legacy shadow восстановлен и удалён", {
            path: this.legacyShadowPath,
            recovered: legacy.recoveredFiles.length,
          });
        } catch (err) {
          this.logger?.warn("session", "legacy shadow восстановлен, но удалить каталог не удалось", {
            path: this.legacyShadowPath,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      } else {
        this.logger?.warn("session", "legacy shadow: часть файлов не восстановлена — каталог оставлен для повторного recovery", {
          path: this.legacyShadowPath,
          failed: legacy.failedFiles.length,
        });
      }
    }

    return result;
  }

  /** Recovery-проход по одному shadow-корню (текущему или legacy). */
  private async recoverFromShadowRoot(shadowRootAbs: string): Promise<CrashRecoveryResult> {
    const recoveredFiles: string[] = [];
    const failedFiles:    string[] = [];
    const corruptedShadow: string[] = [];

    if (!(await fileExists(shadowRootAbs))) {
      return { recoveredFiles, failedFiles, corruptedShadow };
    }

    const shadowFiles = await this.scanShadowFilesIn(shadowRootAbs);

    for (const normalizedPath of shadowFiles) {
      const shadowAbs      = nodePath.join(shadowRootAbs,     ...normalizedPath.split("/"));
      const originalEncAbs = nodePath.join(this.originalRoot, ...normalizedPath.split("/")) + ".enc";

      try {
        // ── Этап 0: фильтр по mtime ───────────────────────────────────────
        const shadowStat   = await fsp.stat(shadowAbs);
        const originalStat = await fsp.stat(originalEncAbs).catch(() => null);

        if (originalStat && shadowStat.mtimeMs <= originalStat.mtimeMs + MTIME_TOLERANCE_MS) {
          continue;
        }

        // ── Этап 1: семантическая сверка с расшифрованным оригиналом ──────
        const shadowBuf = await fsp.readFile(shadowAbs);
        const originalBuf = await this.tryDecryptOriginal(originalEncAbs);

        const semantic = compareSemantic(shadowBuf, originalBuf);
        if (semantic.kind === "equal") {
          // Контент одинаков несмотря на mtime → ничего не делаем
          continue;
        }

        // ── Этап 2: проверка целостности shadow ───────────────────────────
        const integrity = checkFileIntegrity(normalizedPath, shadowBuf);
        if (!integrity.ok) {
          corruptedShadow.push(normalizedPath);
          this.logger?.warn("session", "recovery: shadow повреждён, оригинал не трогаем", {
            path: normalizedPath,
            reason: integrity.reason,
          });
          continue;
        }

        // ── Запись: shadow прошёл проверки → шифруем в оригинал ───────────
        const encrypted = this.engine.encryptBuffer(shadowBuf);
        await atomicWrite(originalEncAbs, encrypted, ".sessiontmp");

        recoveredFiles.push(normalizedPath);
        this.logger?.debug("session", "recovery: файл восстановлен", {
          path: normalizedPath,
          reason: semantic.kind === "different" ? semantic.reason : semantic.kind,
        });
      } catch (err) {
        failedFiles.push(normalizedPath);
        this.logger?.error("session", "recovery файла не удался", {
          path: normalizedPath,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return { recoveredFiles, failedFiles, corruptedShadow };
  }

  /**
   * Пытается расшифровать оригинал во временный файл и вернуть его содержимое.
   * Возвращает null если файла нет ИЛИ расшифровка/AuthTag-проверка провалилась.
   * Используется в Этапе 1 recovery — нужен только plaintext оригинала, не его shadow-копия.
   */
  private async tryDecryptOriginal(encAbsPath: string): Promise<Buffer | null> {
    if (!(await fileExists(encAbsPath))) return null;

    const stat = await fsp.stat(encAbsPath);
    if (stat.size === 0) return Buffer.alloc(0);

    const tmpPath = nodePath.join(
      os.tmpdir(),
      `shadowvault-recover-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    );
    try {
      await this.engine.decryptStream(encAbsPath, tmpPath);
      return await fsp.readFile(tmpPath);
    } catch (err) {
      this.logger?.warn("session", "recovery: оригинал не расшифровался", {
        path: encAbsPath,
        error: err instanceof Error ? err.message : String(err),
      });
      return null;
    } finally {
      await fsp.unlink(tmpPath).catch(() => undefined);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Приватные вспомогательные методы
  // ═══════════════════════════════════════════════════════════════════════

  private async createSessionFile(): Promise<void> {
    const content: SessionFileContent = {
      startedAt:  new Date().toISOString(),
      shadowRoot: this.shadowRoot,
      pid:        process.pid,
    };
    // mkdir на случай если папка плагина ещё не создана (свежая установка)
    await fsp.mkdir(nodePath.dirname(this.sessionFilePath), { recursive: true });
    await atomicWrite(
      this.sessionFilePath,
      Buffer.from(JSON.stringify(content, null, 2), "utf8"),
      ".sessiontmp"
    );
  }

  private async removeSessionFile(): Promise<void> {
    try {
      await fsp.unlink(this.sessionFilePath);
    } catch {
      // Файл уже удалён или не существовал — это нормально
    }
  }

  /**
   * Рекурсивно сканирует Теневое хранилище и возвращает список normalizedPath.
   * Исключает ТОЛЬКО служебные артефакты (единый фильтр isServiceEntryName):
   * .obsidian (конфиг живёт в оригинале через symlink), временные файлы.
   *
   * Пользовательские dot-пути (.trash, .git и т.п.) ВКЛЮЧАЮТСЯ — recovery
   * должен восстанавливать и их, иначе содержимое корзины, пережившее краш,
   * терялось бы при последующем resetShadow. Фильтр симметричен
   * ShadowVaultManager.scanShadowFilesForSync (encrypt-back).
   */
  async scanShadowFiles(relDir = ""): Promise<string[]> {
    return this.scanShadowFilesIn(this.shadowRoot, relDir);
  }

  /** Тот же скан для произвольного shadow-корня (текущий или legacy-сиблинг). */
  private async scanShadowFilesIn(rootAbs: string, relDir = ""): Promise<string[]> {
    const result: string[] = [];
    const absDir = relDir
      ? nodePath.join(rootAbs, ...relDir.split("/"))
      : rootAbs;

    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(absDir, { withFileTypes: true });
    } catch {
      return result;
    }

    const prefix = relDir ? relDir + "/" : "";

    for (const entry of entries) {
      // Пропускаем служебные артефакты (configDir, tmp, маркеры сессии).
      // Симлинки не проходят ни isDirectory(), ни isFile() — отсекаются сами.
      if (isServiceEntryName(entry.name, this.configDir)) continue;

      const rel = prefix + entry.name;
      if (entry.isDirectory()) {
        const sub = await this.scanShadowFilesIn(rootAbs, rel);
        result.push(...sub);
      } else if (entry.isFile()) {
        result.push(rel);
      }
    }

    return result;
  }

  /**
   * Рекурсивно удаляет Теневое хранилище.
   * Использует fs.rm с force=true, чтобы не падать на частично удалённых деревьях.
   */
  private async deleteShadowVault(): Promise<void> {
    if (!(await fileExists(this.shadowRoot))) return;

    await fsp.rm(this.shadowRoot, { recursive: true, force: true });
  }
}

