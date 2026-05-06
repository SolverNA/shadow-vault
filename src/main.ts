/**
 * ShadowVault — плагин прозрачного шифрования для Obsidian.
 *
 * Точка входа. Здесь происходит:
 *   1. Загрузка настроек из data.json.
 *   2. Показ InitModal (блокирует workspace до ввода пароля).
 *   3. После разблокировки: инициализация всех модулей в строгом порядке.
 *   4. Регистрация хуков завершения работы.
 *   5. Предоставление команды "Заблокировать" из палитры команд.
 *
 * Порядок инициализации (важен):
 *   AuthResult (engine) →
 *   ShadowVaultManager.initialize() →
 *   ShadowVaultManager.patch(adapter) ← патчим ДО startSession,
 *     чтобы recovery-операции (re-encrypt) тоже шли через защищённый путь →
 *   SessionManager.startSession() →
 *   QueueIntegration.setup() (сканирует и запускает фоновую расшифровку)
 *
 * Порядок завершения (также важен):
 *   QueueIntegration.teardown() →
 *   ShadowVaultManager.unpatch(adapter) →
 *   SessionManager.endSession() ← ключ уничтожается последним
 */

import * as fs from "fs";
import * as fsp from "fs/promises";
import * as nodePath from "path";
import { App, Notice, Plugin, TFile } from "obsidian";
import { CryptoEngine } from "./crypto-engine";
import { AuthResult } from "./auth-service";
import { InitModal } from "./init-modal";
import { ShadowVaultManager } from "./shadow-vault-manager";
import { SessionManager } from "./session-manager";
import { QueueManager } from "./queue-manager";
import { QueueIntegration } from "./queue-integration";
import { ShadowVaultSettingTab } from "./settings-tab";
import { DEFAULT_SETTINGS, PluginSettings, VERIFICATION_PLAINTEXT } from "./types";
import { IDataAdapter, ListedFiles } from "./adapter-types";
import { AuthService, PasswordError } from "./auth-service";

export default class ShadowVaultPlugin extends Plugin {
  /** Настройки плагина — читаются из data.json, записываются через saveSettings() */
  settings: PluginSettings = { ...DEFAULT_SETTINGS };

  // Модули, создаются только после успешной аутентификации
  private shadowManager:    ShadowVaultManager | null = null;
  private sessionManager:   SessionManager     | null = null;
  private queueIntegration: QueueIntegration   | null = null;

  /** true только пока сессия активна (между onUnlock и shutdown) */
  private sessionActive = false;

  /**
   * Ссылка на оригинальный adapter.list() до ранней подмены.
   * Нужна чтобы перед полным патчингом восстановить настоящий оригинал,
   * иначе unpatch() вернёт раннюю подмену вместо нетронутого метода.
   */
  private earlyListOriginal: ((path: string) => Promise<ListedFiles>) | null = null;

  // ═══════════════════════════════════════════════════════════════════════
  // Жизненный цикл плагина
  // ═══════════════════════════════════════════════════════════════════════

  async onload(): Promise<void> {
    await this.loadSettings();

    // Подменяем adapter.list() ДО того как Obsidian построит индекс файлов.
    // Без этого при первом запуске Obsidian видит только .enc файлы и создаёт пустой индекс.
    // Ранняя подмена только транслирует имена (.enc → .md), ключ шифрования не нужен.
    this.patchListEarly();

    // Вкладка настроек появляется всегда, независимо от состояния блокировки
    this.addSettingTab(new ShadowVaultSettingTab(this.app, this));

    // Команда ручной блокировки — доступна только когда сессия активна
    this.addCommand({
      id: "lock-vault",
      name: "Заблокировать хранилище",
      checkCallback: (checking: boolean) => {
        if (!this.sessionActive) return false;
        if (!checking) this.lockVault();
        return true;
      },
    });

    // Показываем модал ввода пароля когда workspace готов к отображению UI
    this.app.workspace.onLayoutReady(() => {
      this.openInitModal();
    });

    console.info("[ShadowVault] Плагин загружен, ожидаем пароль.");
  }

  async onunload(): Promise<void> {
    // onunload может быть вызван синхронно при закрытии Obsidian.
    // Мы инициируем shutdown, но не можем гарантировать его завершение
    // если Obsidian закрывается агрессивно. .session_active останется на диске
    // и запустит recovery при следующем запуске — это корректное поведение.
    this.shutdown().catch((err) => {
      console.error("[ShadowVault] Ошибка при завершении сессии:", err);
    });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Публичный API (используется в settings-tab и тестах)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Немедленно завершает сессию: удаляет теневое хранилище, уничтожает ключ,
   * затем снова показывает InitModal.
   */
  async lockVault(): Promise<void> {
    await this.shutdown();
    // После блокировки показываем модал повторно (без перезапуска Obsidian)
    this.openInitModal();
  }

  isUnlocked(): boolean {
    return this.sessionActive;
  }

  /**
   * Меняет пароль хранилища: пере-шифровывает все .enc файлы с новым ключом.
   * Вызывать только при активной сессии.
   * После успеха блокирует хранилище — пользователь должен войти с новым паролем.
   *
   * @throws PasswordError если oldPassword неверный
   */
  async changePassword(
    oldPassword: string,
    newPassword: string,
    onProgress: (done: number, total: number) => void
  ): Promise<void> {
    if (!this.sessionActive) {
      throw new Error("Хранилище не разблокировано.");
    }

    // 1. Верифицируем старый пароль независимо от активной сессии —
    //    защита от смены пароля на разблокированном чужом устройстве
    const checkEngine = new CryptoEngine();
    try {
      await checkEngine.deriveKey(oldPassword, this.settings.saltHex!);
      const decrypted = checkEngine.decryptBuffer(
        Buffer.from(this.settings.verificationBlob!, "hex")
      );
      if (decrypted.toString("utf8") !== VERIFICATION_PLAINTEXT) {
        throw new PasswordError("Неверный текущий пароль.");
      }
    } catch (err) {
      checkEngine.destroy();
      if (err instanceof PasswordError) throw err;
      throw new PasswordError("Неверный текущий пароль.");
    }
    checkEngine.destroy();

    // 2. Создаём движок с новым паролем
    const newEngine = new CryptoEngine();
    const newSaltHex = await newEngine.deriveKey(newPassword);

    // 3. Пере-шифруем все файлы (двухфазно, атомарно)
    try {
      await this.shadowManager!.reEncryptAll(newEngine, onProgress);
    } catch (err) {
      newEngine.destroy();
      throw err;
    }

    // 4. Сохраняем новые настройки — только после успешной пере-шифровки
    const newVerificationBuf = newEngine.encryptBuffer(
      Buffer.from(VERIFICATION_PLAINTEXT, "utf8")
    );
    await this.saveSettings({
      ...this.settings,
      saltHex: newSaltHex,
      verificationBlob: newVerificationBuf.toString("hex"),
    });

    newEngine.destroy();

    // 5. Блокируем — при следующем входе используется новый пароль
    await this.lockVault();
  }

  async loadSettings(): Promise<void> {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings(updated?: PluginSettings): Promise<void> {
    if (updated) this.settings = updated;
    await this.saveData(this.settings);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Инициализация после успешной аутентификации
  // ═══════════════════════════════════════════════════════════════════════

  private openInitModal(): void {
    new InitModal(
      this.app,
      this.settings,
      (s) => this.saveSettings(s),
      (result) => this.onUnlock(result)
    ).open();
  }

  /**
   * Колбэк успешной аутентификации. Вызывается InitModal после
   * корректной деривации ключа и верификации пароля.
   *
   * Все операции обёрнуты в try/catch: любая ошибка инициализации
   * должна уничтожить engine и показать понятное сообщение.
   */
  private async onUnlock(result: AuthResult): Promise<void> {
    const { engine, isFirstRun } = result;

    try {
      const basePath = this.getVaultBasePath();
      if (!basePath) {
        new Notice(
          "❌ ShadowVault: getBasePath() недоступен. Плагин работает только на десктопе.",
          10000
        );
        engine.destroy();
        return;
      }

      // ── Шаг 3: VFS-менеджер ─────────────────────────────────────────
      this.shadowManager = new ShadowVaultManager(
        engine,
        basePath,
        this.settings.shadowVaultPath || undefined
      );
      await this.shadowManager.initialize();

      // Миграция: если в оригинальном хранилище есть незашифрованные файлы
      // (первая установка плагина на существующий vault) — шифруем их.
      // Это КРИТИЧНО: без шифрования оригиналов пользователь видит заметки без пароля.
      if (await this.shadowManager.hasPendingMigration()) {
        new Notice("⏳ ShadowVault: шифруем существующие файлы хранилища...", 5000);
        await this.shadowManager.encryptAllExisting();
        new Notice("✅ ShadowVault: все файлы зашифрованы.", 4000);
      }

      // Перед полным патчингом восстанавливаем оригинальный list(),
      // иначе shadowManager.patch() сохранит раннюю подмену и unpatch()
      // при блокировке вернёт её, показывая файлы без пароля.
      const adapterForPatch = this.app.vault.adapter as unknown as IDataAdapter;
      if (this.earlyListOriginal) {
        adapterForPatch.list = this.earlyListOriginal;
      }

      // Патчим адаптер ДО startSession — чтобы операции recovery шли
      // через правильные пути (bypass для .obsidian и т.д.)
      this.shadowManager.patch(adapterForPatch);

      // ── Шаг 5: Управление сессией и crash recovery ──────────────────
      this.sessionManager = new SessionManager(
        engine,
        basePath,
        this.shadowManager.shadowRoot
      );
      const sessionResult = await this.sessionManager.startSession();

      if (sessionResult.hadCrash) {
        this.notifyCrashRecovery(sessionResult.recovery!);
      }

      // ── Шаг 4: Фоновая расшифровка с приоритетами ───────────────────
      const queueManager = new QueueManager(
        (normalizedPath: string) => this.shadowManager!.ensureDecrypted(normalizedPath),
        { concurrency: 3 }
      );
      this.queueIntegration = new QueueIntegration(
        this.app,
        this,
        queueManager,
        this.shadowManager
      );
      await this.queueIntegration.setup();

      // ── Переиндексация файлового индекса Obsidian ────────────────────
      // Obsidian строит индекс TFile-объектов ДО того, как наш патч активен.
      // После патча adapter.list() уже возвращает правильные .md пути,
      // но индекс устарел. Отправляем "raw" событие для каждого файла —
      // Obsidian проверит stat() и создаст недостающие TFile-записи.
      await this.reconcileVaultIndex();

      // ── Хук beforeunload (дополнительно к onunload) ─────────────────
      // Electron не всегда вызывает plugin.onunload() при закрытии окна
      this.registerDomEvent(window as Window, "beforeunload", () => {
        this.shutdown();
      });

      this.sessionActive = true;

      // ── Уведомление пользователя ────────────────────────────────────
      if (isFirstRun) {
        new Notice("🔐 ShadowVault: хранилище создано! Пароль сохранён.", 5000);
      } else {
        new Notice("🔓 ShadowVault: хранилище разблокировано.", 2500);
      }

      console.info(
        `[ShadowVault] Сессия запущена. Shadow: ${this.shadowManager.shadowRoot}`
      );
    } catch (err) {
      console.error("[ShadowVault] Ошибка инициализации:", err);
      new Notice(
        `❌ ShadowVault: ошибка при запуске.\n${err instanceof Error ? err.message : String(err)}`,
        10000
      );
      // Если что-то пошло не так, убираем частично созданное состояние
      engine.destroy();
      if (this.shadowManager) {
        this.shadowManager.unpatch(
          this.app.vault.adapter as unknown as IDataAdapter
        );
        this.shadowManager = null;
      }
      this.sessionManager = null;
      this.queueIntegration = null;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Завершение сессии
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Завершает активную сессию. Безопасно вызывать несколько раз —
   * повторные вызовы — no-op если сессия уже неактивна.
   *
   * Порядок операций строго определён:
   *   1. QueueIntegration.teardown() — останавливаем фоновые процессы
   *   2. ShadowVaultManager.unpatch() — восстанавливаем оригинальный адаптер
   *      ПЕРЕД удалением shadow vault, чтобы Obsidian не обращался к нему
   *   3. SessionManager.endSession() — удаляем shadow vault, уничтожаем ключ
   */
  async shutdown(): Promise<void> {
    if (!this.sessionActive) return;
    this.sessionActive = false;

    console.info("[ShadowVault] Завершение сессии...");

    // 1. Останавливаем очередь и снимаем хуки UI
    try {
      this.queueIntegration?.teardown();
    } catch (err) {
      console.error("[ShadowVault] teardown QueueIntegration:", err);
    } finally {
      this.queueIntegration = null;
    }

    // 2. Снимаем патч с адаптера
    try {
      if (this.shadowManager) {
        this.shadowManager.unpatch(
          this.app.vault.adapter as unknown as IDataAdapter
        );
      }
    } catch (err) {
      console.error("[ShadowVault] unpatch адаптера:", err);
    } finally {
      this.shadowManager = null;
    }

    // 3. Удаляем shadow vault и уничтожаем ключ
    try {
      await this.sessionManager?.endSession();
    } catch (err) {
      console.error("[ShadowVault] endSession:", err);
    } finally {
      this.sessionManager = null;
    }

    console.info("[ShadowVault] Сессия завершена.");
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Вспомогательные методы
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Возвращает абсолютный путь к директории хранилища Obsidian.
   * Доступен только в десктопной версии через FileSystemAdapter.getBasePath().
   */
  private getVaultBasePath(): string | null {
    const adapter = this.app.vault.adapter as unknown as IDataAdapter;
    if (typeof adapter.getBasePath === "function") {
      return adapter.getBasePath();
    }
    return null;
  }

  private notifyCrashRecovery(
    recovery: { recoveredFiles: string[]; failedFiles: string[] }
  ): void {
    const { recoveredFiles, failedFiles } = recovery;

    if (recoveredFiles.length === 0 && failedFiles.length === 0) {
      // Краш был, но потерянных данных нет — тихо пропускаем
      return;
    }

    let msg = `⚠️ ShadowVault: обнаружен сбой предыдущей сессии.\n`;
    if (recoveredFiles.length > 0) {
      msg += `✅ Восстановлено файлов: ${recoveredFiles.length}.\n`;
    }
    if (failedFiles.length > 0) {
      msg += `❌ Не удалось восстановить: ${failedFiles.length}.\n`;
      msg += `Проверьте консоль разработчика для деталей.`;
    }

    new Notice(msg, 10000);
  }

  /**
   * Подменяет adapter.list() сразу при загрузке плагина, до ввода пароля.
   * Obsidian строит индекс файлов (TFile-объекты) при запуске — если в этот
   * момент adapter.list() возвращает только .enc имена, индекс будет пустым.
   * Ранняя подмена транслирует .enc → .md без ключа шифрования, только
   * переименование, чтобы первичный скан видел правильные имена файлов.
   */
  private patchListEarly(): void {
    const adapter = this.app.vault.adapter as unknown as IDataAdapter;
    if (typeof adapter.getBasePath !== "function") return;

    const originalRoot = adapter.getBasePath();
    const originalList = adapter.list.bind(adapter);
    this.earlyListOriginal = originalList;

    console.info("[ShadowVault:early] patchListEarly установлен, root:", originalRoot);

    adapter.list = async (normalizedPath: string): Promise<ListedFiles> => {
      if (normalizedPath !== "" && (
        normalizedPath === ".obsidian" ||
        normalizedPath.startsWith(".obsidian/")
      )) {
        return originalList(normalizedPath);
      }

      const absDir = normalizedPath
        ? nodePath.join(originalRoot, ...normalizedPath.split("/"))
        : originalRoot;

      const files: string[] = [];
      const folders: string[] = [];

      let entries: fs.Dirent[];
      try {
        entries = await fsp.readdir(absDir, { withFileTypes: true });
      } catch {
        return { files: [], folders: [] };
      }

      const prefix = normalizedPath ? normalizedPath + "/" : "";
      for (const entry of entries) {
        if (entry.name.startsWith(".") && entry.name !== ".obsidian") continue;
        if (
          entry.name.endsWith(".tmp")       ||
          entry.name.endsWith(".shadowtmp") ||
          entry.name.endsWith(".sessiontmp")
        ) continue;

        if (entry.isDirectory()) {
          folders.push(prefix + entry.name);
        } else if (entry.isFile() && entry.name.endsWith(".enc")) {
          const baseName = entry.name.slice(0, -".enc".length);
          files.push(prefix + baseName);
        }
      }

      return { files, folders };
    };
  }

  /**
   * Принудительно добавляет .md файлы в индекс Obsidian.
   *
   * Почему raw-события не работают:
   *   reconcileFileInternal() вызывает нативный fsPromises.lstat() через original-fs.
   *   note.md физически не существует на диске (только note.md.enc), поэтому
   *   Obsidian всегда получает ENOENT и игнорирует path.
   *
   * Правильный путь: слать adapter.trigger("file-created") напрямую.
   *   Vault подписан на это событие адаптера и создаёт TFile в fileMap
   *   без проверки нативного FS.
   */
  private async reconcileVaultIndex(): Promise<void> {
    const adapter = this.app.vault.adapter as any;
    if (typeof adapter.trigger !== "function") return;
    try {
      await this.notifyFilesCreated("", adapter);
    } catch (err) {
      console.warn("[ShadowVault] reconcileVaultIndex:", err);
    }
  }

  private async notifyFilesCreated(dir: string, adapter: any): Promise<void> {
    const listed = await this.app.vault.adapter.list(dir);

    // Сначала папки — чтобы vault.getDirectParent() нашёл родителя для файлов
    for (const folderPath of listed.folders) {
      if (!adapter.files?.[folderPath]) {
        adapter.files ??= {};
        adapter.files[folderPath] = { type: "folder", realpath: folderPath };
        adapter.trigger("folder-created", folderPath);
      }
      await this.notifyFilesCreated(folderPath, adapter);
    }

    for (const filePath of listed.files) {
      // Пропускаем если адаптер уже знает этот path (напр. файлы .obsidian)
      if (adapter.files?.[filePath]) continue;

      // Читаем метаданные из .enc файла в оригинальном хранилище
      const origEncPath = this.shadowManager!.originalEncAbs(filePath);
      let statObj = { ctime: Date.now(), mtime: Date.now(), size: 0 };
      try {
        const s = await fsp.stat(origEncPath);
        statObj = {
          ctime: Math.round(s.birthtimeMs ?? s.ctimeMs),
          mtime: Math.round(s.mtimeMs),
          size:  Math.max(0, s.size - 28), // минус заголовок IV+AuthTag
        };
      } catch { /* enc файл не найден — используем заглушку */ }

      adapter.files ??= {};
      adapter.files[filePath] = { type: "file", realpath: filePath, ...statObj };
      // vault слушает "file-created" → создаёт TFile, добавляет в fileMap, стреляет "create"
      adapter.trigger("file-created", filePath, filePath, statObj);
    }
  }
}
