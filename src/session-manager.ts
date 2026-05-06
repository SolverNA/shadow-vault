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
import { CryptoEngine } from "./crypto-engine";

/** Имя файла-индикатора активной сессии */
const SESSION_FILE = ".session_active";

/** JSON-структура файла .session_active */
interface SessionFileContent {
  startedAt: string;   // ISO-строка
  shadowRoot: string;  // абсолютный путь к теневому хранилищу
}

export interface CrashRecoveryResult {
  /** Пути файлов, которые были успешно перешифрованы */
  recoveredFiles: string[];
  /** Пути файлов, которые не удалось восстановить (ошибки шифрования/ФС) */
  failedFiles:    string[];
}

export interface SessionStartResult {
  /** true если обнаружен краш предыдущей сессии */
  hadCrash: boolean;
  /** Результат восстановления (только при hadCrash=true) */
  recovery?: CrashRecoveryResult;
}

export class SessionManager {
  private readonly sessionFilePath: string;

  constructor(
    private readonly engine:       CryptoEngine,
    private readonly originalRoot: string,
    private readonly shadowRoot:   string
  ) {
    this.sessionFilePath = nodePath.join(originalRoot, SESSION_FILE);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Публичный API
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Вызывается при старте плагина после успешной деривации ключа.
   *
   * Алгоритм:
   *   1. Проверяем наличие .session_active → если есть: запускаем recovery.
   *   2. Создаём новый .session_active с меткой времени и путём к shadow.
   *   3. Возвращаем результат (был ли краш и что восстановлено).
   */
  async startSession(): Promise<SessionStartResult> {
    let hadCrash = false;
    let recovery: CrashRecoveryResult | undefined;

    const sessionFileExists = await fileExists(this.sessionFilePath);

    if (sessionFileExists) {
      // Предыдущая сессия не завершилась корректно
      hadCrash = true;
      console.warn("[SessionManager] Обнаружен краш предыдущей сессии. Запускаем Crash Recovery...");
      recovery = await this.recoverFromCrash();
      console.info(
        `[SessionManager] Recovery завершён: ${recovery.recoveredFiles.length} файлов восстановлено, ` +
        `${recovery.failedFiles.length} ошибок.`
      );
    }

    // Создаём новый файл-индикатор для текущей сессии
    await this.createSessionFile();

    return { hadCrash, recovery };
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
   */
  async endSession(): Promise<void> {
    let shadowDeleted = false;

    try {
      await this.deleteShadowVault();
      shadowDeleted = true;
    } catch (err) {
      console.error(
        "[SessionManager] Не удалось полностью удалить Теневое хранилище:",
        err
      );
    }

    if (shadowDeleted) {
      // Только после успешного удаления shadow снимаем флаг сессии
      await this.removeSessionFile();
    } else {
      console.warn(
        "[SessionManager] .session_active НЕ удалён — при следующем запуске будет recovery."
      );
    }

    // Ключ обнуляется в любом случае
    this.engine.destroy();
  }

  /**
   * Crash Recovery: находит и восстанавливает «потерянные» записи.
   *
   * «Потерянный» файл = файл в Теневом хранилище, чей mtime
   * строго новее соответствующего файла в Оригинальном хранилище.
   *
   * Это означает: write-through записал данные в shadow, но не успел
   * атомарно обновить оригинал до краша питания/приложения.
   *
   * После recovery shadow vault не удаляется — его чистит endSession().
   * startSession() вызывает recoverFromCrash() ДО создания нового .session_active,
   * поэтому recovery идёт в «чистом» состоянии.
   */
  async recoverFromCrash(): Promise<CrashRecoveryResult> {
    const recoveredFiles: string[] = [];
    const failedFiles:    string[] = [];

    // Теневое хранилище могло не существовать (краш до инициализации)
    if (!(await fileExists(this.shadowRoot))) {
      return { recoveredFiles, failedFiles };
    }

    const shadowFiles = await this.scanShadowFiles();

    for (const normalizedPath of shadowFiles) {
      const shadowAbs   = nodePath.join(this.shadowRoot,   ...normalizedPath.split("/"));
      const originalAbs = nodePath.join(this.originalRoot, ...normalizedPath.split("/"));

      try {
        const shadowStat   = await fsp.stat(shadowAbs);
        const originalStat = await fsp.stat(originalAbs).catch(() => null);

        const shadowMtime   = shadowStat.mtimeMs;
        const originalMtime = originalStat?.mtimeMs ?? 0;

        // Файл считается «потерянным» если shadow строго новее оригинала.
        // Небольшой допуск 50 мс для учёта погрешности файловой системы.
        const TOLERANCE_MS = 50;
        if (shadowMtime <= originalMtime + TOLERANCE_MS) {
          // Оригинал актуален — восстанавливать нечего
          continue;
        }

        // Шифруем shadow → tmp → оригинал (атомарно)
        const plaintext = await fsp.readFile(shadowAbs);
        const encrypted = this.engine.encryptBuffer(plaintext);
        await atomicWrite(originalAbs, encrypted);

        recoveredFiles.push(normalizedPath);
        console.info(`[SessionManager] Восстановлен: "${normalizedPath}"`);
      } catch (err) {
        failedFiles.push(normalizedPath);
        console.error(`[SessionManager] Ошибка recovery для "${normalizedPath}":`, err);
      }
    }

    return { recoveredFiles, failedFiles };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Приватные вспомогательные методы
  // ═══════════════════════════════════════════════════════════════════════

  private async createSessionFile(): Promise<void> {
    const content: SessionFileContent = {
      startedAt:  new Date().toISOString(),
      shadowRoot: this.shadowRoot,
    };
    // Атомарная запись: не хотим частично записанного .session_active
    await atomicWrite(
      this.sessionFilePath,
      Buffer.from(JSON.stringify(content, null, 2), "utf8")
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
   * Исключает: .obsidian/*, скрытые системные файлы, директории.
   */
  async scanShadowFiles(relDir = ""): Promise<string[]> {
    const result: string[] = [];
    const absDir = relDir
      ? nodePath.join(this.shadowRoot, ...relDir.split("/"))
      : this.shadowRoot;

    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(absDir, { withFileTypes: true });
    } catch {
      return result;
    }

    const prefix = relDir ? relDir + "/" : "";

    for (const entry of entries) {
      // Пропускаем скрытые служебные файлы и .obsidian
      if (entry.name.startsWith(".")) continue;

      const rel = prefix + entry.name;
      if (entry.isDirectory()) {
        const sub = await this.scanShadowFiles(rel);
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

// ═══════════════════════════════════════════════════════════════════════
// Модульные утилиты
// ═══════════════════════════════════════════════════════════════════════

async function fileExists(absPath: string): Promise<boolean> {
  try {
    await fsp.access(absPath);
    return true;
  } catch {
    return false;
  }
}

/** Атомарная запись через tmp + rename — та же гарантия что в ShadowVaultManager */
async function atomicWrite(absPath: string, data: Buffer): Promise<void> {
  await fsp.mkdir(nodePath.dirname(absPath), { recursive: true });
  const tmpPath = absPath + ".sessiontmp";
  try {
    await fsp.writeFile(tmpPath, data);
    await fsp.rename(tmpPath, absPath);
  } catch (err) {
    await fsp.unlink(tmpPath).catch(() => undefined);
    throw err;
  }
}
