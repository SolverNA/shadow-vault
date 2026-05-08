/**
 * ShadowVault — плагин прозрачного шифрования для Obsidian.
 *
 * Архитектура:
 *   Оригинальное хранилище (originalRoot)  — содержит .enc + plaintext .obsidian/
 *   Теневое хранилище (shadowRoot)         — сиблинг оригинала, расшифрованный клон
 *
 *   После unlock плагин расшифровывает ВСЁ в shadow и монтирует shadow как
 *   adapter.basePath — Obsidian работает с shadow натив но (включая getResourcePath
 *   для картинок/PDF). Параллельно patch() ставит write-through encrypt в оригинал.
 *
 * Порядок инициализации (важен):
 *   AuthResult (engine) →
 *   ShadowVaultManager.initialize() →
 *   miграция plaintext (если есть) →
 *   decryptAllToShadow() — расшифровываем .enc → shadow →
 *   setupObsidianSymlink() — shadow/.obsidian → original/.obsidian →
 *   mount(adapter) — adapter.basePath = shadowRoot →
 *   patch(adapter) — write-through encrypt в оригинал →
 *   SessionManager.startSession() — recovery + .session_active
 *
 * Порядок завершения (также важен):
 *   encryptShadowChangesToOriginal() — финальная синхронизация изменений →
 *   unpatch + unmount(adapter) — восстанавливаем оригинальный basePath →
 *   teardownObsidianSymlink() →
 *   SessionManager.endSession() — удаление shadow + ключ destroy
 */

import * as fs from "fs";
import * as fsp from "fs/promises";
import * as nodePath from "path";
import { Notice, Plugin } from "obsidian";
import { CryptoEngine } from "./crypto-engine";
import { AuthResult, AuthService } from "./auth-service";
import { InitModal } from "./init-modal";
import { ShadowVaultManager } from "./shadow-vault-manager";
import { SessionManager } from "./session-manager";
import { ShadowVaultSettingTab } from "./settings-tab";
import { DEFAULT_SETTINGS, PluginSettings, VERIFICATION_PLAINTEXT } from "./types";
import { IDataAdapter, ListedFiles } from "./adapter-types";
import { ENCRYPTED_EXT, isTempFile } from "./fs-utils";

export default class ShadowVaultPlugin extends Plugin {
  /** Настройки плагина — читаются из data.json, записываются через saveSettings() */
  settings: PluginSettings = { ...DEFAULT_SETTINGS };

  // Модули, создаются только после успешной аутентификации
  private shadowManager:    ShadowVaultManager | null = null;
  private sessionManager:   SessionManager     | null = null;

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
        if (!checking) void this.lockVault();
        return true;
      },
    });

    // Показываем модал ввода пароля когда workspace готов к отображению UI
    this.app.workspace.onLayoutReady(() => {
      this.openInitModal();
    });

    console.debug("[ShadowVault] Плагин загружен, ожидаем пароль.");
  }

  onunload(): void {
    // Obsidian закрывается агрессивно и НЕ ждёт async-shutdown — поэтому
    // используем sync-версию очистки. Write-through уже сохранил все
    // изменения в оригинал на каждый save, на shutdown остаётся только
    // удалить shadow и lock — это всё делается синхронно через fs.*Sync.
    if (this.sessionActive) {
      this.syncCleanup();
    }
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
    const checkEngine = await AuthService.verifyPassword(oldPassword, this.settings);
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
      (result) => { void this.onUnlock(result); }
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

    const basePath = this.getVaultBasePath();
    if (!basePath) {
      new Notice(
        "❌ Shadow Vault: getBasePath() недоступен, плагин работает только на десктопе.",
        10000
      );
      engine.destroy();
      return;
    }

    try {
      await this.setupShadow(engine, basePath);
      await this.setupSession(engine, basePath);
      // Bulk decrypt уже расшифровал всё в shadow ДО mount, и patchListEarly
      // уже наполнил vault.fileMap транслированными именами при первичном скане.
      // После mount Obsidian читает shadow натив но — никаких ручных
      // file-created/folder-created триггеров не нужно (они были источником
      // багов: .obsidian регистрировался как обычная папка, fileMap получал
      // дубли, "already exists" при создании заметок).

      // Electron не всегда вызывает plugin.onunload() при закрытии окна.
      // Используем sync cleanup — асинхронный shutdown не успевает завершиться.
      this.registerDomEvent(window as Window, "beforeunload", () => {
        if (this.sessionActive) this.syncCleanup();
      });

      this.sessionActive = true;

      if (isFirstRun) {
        new Notice("🔐 Shadow Vault: хранилище создано, пароль сохранён.", 5000);
      } else {
        new Notice("🔓 Shadow Vault: хранилище разблокировано.", 2500);
      }

      console.debug(
        `[ShadowVault] Сессия запущена. Shadow: ${this.shadowManager!.shadowRoot}`
      );
    } catch (err) {
      console.error("[ShadowVault] Ошибка инициализации:", err);
      new Notice(
        `❌ Shadow Vault: ошибка при запуске.\n${err instanceof Error ? err.message : String(err)}`,
        10000
      );
      this.rollbackInitialization(engine);
    }
  }

  /** Создаёт ShadowVaultManager, проводит миграцию (если нужна), расшифровывает оригинал в shadow, монтирует shadow как basePath и патчит адаптер для write-through. */
  private async setupShadow(engine: CryptoEngine, basePath: string): Promise<void> {
    this.shadowManager = new ShadowVaultManager(
      engine,
      basePath,
      this.settings.shadowVaultPath || undefined,
      this.app.vault.configDir
    );
    await this.shadowManager.initialize();

    // 1. Миграция первичной установки: шифруем plaintext-файлы существующего vault
    if (await this.shadowManager.hasPendingMigration()) {
      new Notice("⏳ Shadow Vault: шифруем существующие файлы хранилища...", 5000);
      await this.shadowManager.encryptAllExisting();
      new Notice("✅ Shadow Vault: все файлы зашифрованы.", 4000);
    }

    // 2. Восстанавливаем оригинальный list() до полного патчинга
    const adapter = this.app.vault.adapter as unknown as IDataAdapter;
    if (this.earlyListOriginal) {
      adapter.list = this.earlyListOriginal;
    }

    // 3. Bulk decrypt: расшифровываем ВСЁ в shadow ПЕРЕД mount.
    //    Так Obsidian увидит готовое хранилище плейнтекста и сможет рендерить картинки/PDF
    //    через нативный getResourcePath без дополнительной магии.
    const progressNotice = new Notice("🔓 Shadow Vault: расшифровка хранилища...", 0);
    let result: { decrypted: string[]; failed: Array<{ path: string; error: string }> };
    try {
      result = await this.shadowManager.decryptAllToShadow((done, total, current) => {
        const percent = total > 0 ? Math.round((done / total) * 100) : 0;
        progressNotice.setMessage(
          `🔓 Расшифровка хранилища: ${done}/${total} (${percent}%)\n${current.slice(-60)}`
        );
      });
    } finally {
      progressNotice.hide();
    }

    if (result.failed.length > 0) {
      new Notice(
        `⚠️ Shadow Vault: ${result.failed.length} файл(ов) не удалось расшифровать. ` +
        `См. консоль разработчика. Хранилище работает в режиме read-only для них.`,
        10000
      );
    }

    // 4. Symlink .obsidian: shadowRoot/.obsidian → originalRoot/.obsidian
    //    Конфиг плагинов/тем/workspace персистится напрямую в оригинале без шифрования
    //    (зашифровать невозможно: Obsidian читает .obsidian ДО загрузки нашего плагина).
    await this.shadowManager.setupObsidianSymlink();

    // 5. Mount: подменяем basePath адаптера на shadow.
    //    После этого все нативные операции Obsidian (read/write/getResourcePath)
    //    идут в shadow — изображения, PDF, attachment'ы рендерятся натив но.
    this.shadowManager.mount(adapter);

    // 6. Patch (страховочный слой поверх mount): write-through encrypt в оригинал.
    //    Когда Obsidian вызывает adapter.write — мы дублируем шифрованную копию в .enc.
    this.shadowManager.patch(adapter);
  }

  /** Запускает SessionManager и обрабатывает crash recovery. */
  private async setupSession(engine: CryptoEngine, basePath: string): Promise<void> {
    this.sessionManager = new SessionManager(
      engine,
      basePath,
      this.shadowManager!.shadowRoot,
      this.getPluginDirAbs(basePath)
    );
    const sessionResult = await this.sessionManager.startSession();

    if (sessionResult.hadCrash) {
      this.notifyCrashRecovery(sessionResult.recovery!);
    }
  }

  /**
   * Абсолютный путь к папке плагина: <vault>/.obsidian/plugins/<id>.
   * Используем для хранения session.lock — чтобы не засорять оригинальное
   * хранилище и не попадать под Obsidian-индексацию.
   */
  private getPluginDirAbs(originalRoot: string): string {
    return nodePath.join(
      originalRoot,
      this.app.vault.configDir,
      "plugins",
      this.manifest.id
    );
  }

  // setupQueue() удалён: bulk decrypt в setupShadow покрывает весь vault единоразово.
  // QueueManager/QueueIntegration оставлены в кодовой базе на случай восстановления
  // lazy-режима в будущем — но не вызываются в текущем flow.

  /** Освобождает частично созданное состояние при ошибке инициализации. */
  private rollbackInitialization(engine: CryptoEngine): void {
    engine.destroy();
    if (this.shadowManager) {
      const adapter = this.app.vault.adapter as unknown as IDataAdapter;
      this.shadowManager.unpatch(adapter);
      this.shadowManager.unmount(adapter);
      this.shadowManager = null;
    }
    this.sessionManager = null;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Завершение сессии
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Завершает активную сессию. Безопасно вызывать несколько раз —
   * повторные вызовы — no-op если сессия уже неактивна.
   *
   * Порядок операций строго определён:
   *   1. encryptShadowChangesToOriginal() — финальная синхронизация изменений
   *      из shadow в оригинал.enc (страховка от пропущенных write-through).
   *   2. unpatch() и unmount() — восстанавливаем адаптер до оригинала,
   *      ПЕРЕД удалением shadow vault, чтобы Obsidian не обращался к нему.
   *   3. teardownObsidianSymlink() — снимаем symlink .obsidian.
   *   4. SessionManager.endSession() — удаляем shadow vault, уничтожаем ключ.
   */
  async shutdown(): Promise<void> {
    if (!this.sessionActive) return;
    this.sessionActive = false;

    console.debug("[ShadowVault] Завершение сессии...");

    // 1. Финальный encrypt-back: страховка на случай если write-through
    //    что-то пропустил (например, файл был изменён сторонним процессом в shadow)
    if (this.shadowManager) {
      try {
        const r = await this.shadowManager.encryptShadowChangesToOriginal();
        if (r.encrypted.length > 0) {
          console.debug(`[ShadowVault] shutdown encrypt-back: ${r.encrypted.length} файлов синхронизировано`);
        }
        if (r.failed.length > 0) {
          console.error("[ShadowVault] shutdown encrypt-back: failed:", r.failed);
          new Notice(
            `⚠️ Shadow Vault: не удалось зашифровать ${r.failed.length} файл(ов) при выходе. ` +
            `Shadow vault сохранён для recovery при следующем запуске.`,
            10000
          );
        }
      } catch (err) {
        console.error("[ShadowVault] shutdown encrypt-back ошибка:", err);
      }
    }

    // 2. Снимаем патч и mount с адаптера
    try {
      if (this.shadowManager) {
        const adapter = this.app.vault.adapter as unknown as IDataAdapter;
        this.shadowManager.unpatch(adapter);
        this.shadowManager.unmount(adapter);
        await this.shadowManager.teardownObsidianSymlink();
      }
    } catch (err) {
      console.error("[ShadowVault] unpatch/unmount адаптера:", err);
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

    console.debug("[ShadowVault] Сессия завершена.");
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
    recovery: { recoveredFiles: string[]; failedFiles: string[]; corruptedShadow: string[] }
  ): void {
    const { recoveredFiles, failedFiles, corruptedShadow } = recovery;

    if (recoveredFiles.length === 0 && failedFiles.length === 0 && corruptedShadow.length === 0) {
      // Краш был, но потерянных данных нет — тихо пропускаем
      return;
    }

    let msg = `⚠️ ShadowVault: обнаружен сбой предыдущей сессии.\n`;
    if (recoveredFiles.length > 0) {
      msg += `✅ Восстановлено файлов: ${recoveredFiles.length}.\n`;
    }
    if (corruptedShadow.length > 0) {
      msg += `⚠️ Битых файлов в теневом хранилище: ${corruptedShadow.length} ` +
             `(использован оригинал, правки могли быть потеряны).\n`;
    }
    if (failedFiles.length > 0) {
      msg += `❌ Не удалось восстановить: ${failedFiles.length}.\n`;
      msg += `Проверьте консоль разработчика для деталей.`;
    }

    new Notice(msg, 12000);
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

    const configDir = this.app.vault.configDir;
    console.debug("[ShadowVault:early] patchListEarly установлен, root:", originalRoot);

    adapter.list = async (normalizedPath: string): Promise<ListedFiles> => {
      if (normalizedPath !== "" && (
        normalizedPath === configDir ||
        normalizedPath.startsWith(configDir + "/")
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
        if (entry.name.startsWith(".") && entry.name !== configDir) continue;
        if (isTempFile(entry.name)) continue;

        if (entry.isDirectory()) {
          folders.push(prefix + entry.name);
        } else if (entry.isFile() && entry.name.endsWith(ENCRYPTED_EXT)) {
          const baseName = entry.name.slice(0, -ENCRYPTED_EXT.length);
          files.push(prefix + baseName);
        }
      }

      return { files, folders };
    };
  }

  /**
   * Синхронная очистка для onunload и beforeunload.
   *
   * Зачем sync: Obsidian/Electron не ждут async-shutdown при закрытии окна.
   * Если делать через Promise — процесс умирает раньше чем мы успеем удалить
   * shadow vault и lock-файл, и при следующем старте срабатывает crash recovery
   * на «фантомный» краш, хотя пользователь просто закрыл приложение.
   *
   * Безопасность данных не страдает: write-through на каждый save уже
   * записал зашифрованную копию в оригинал.enc. Финальный verify-back
   * (encryptShadowChangesToOriginal) — лишь страховка, и он выполняется
   * в lockVault() где у нас есть полноценный async-цикл.
   *
   * Порядок:
   *   1. unpatch + unmount адаптера — Obsidian возвращается к оригинальному basePath.
   *   2. fs.unlinkSync символической ссылки .obsidian (только если это симлинк).
   *   3. fs.rmSync теневого хранилища целиком.
   *   4. fs.unlinkSync session.lock в папке плагина.
   *   5. engine.destroy() — обнуляем ключ в RAM.
   */
  private syncCleanup(): void {
    if (!this.sessionActive) return;
    this.sessionActive = false;

    const adapter = this.app.vault.adapter as unknown as IDataAdapter;

    if (this.shadowManager) {
      // 1. unpatch + unmount
      try { this.shadowManager.unpatch(adapter); } catch (e) { console.error("[ShadowVault] sync unpatch:", e); }
      try { this.shadowManager.unmount(adapter); } catch (e) { console.error("[ShadowVault] sync unmount:", e); }

      // 2. .obsidian symlink — удаляем только если это действительно симлинк
      const symlinkPath = nodePath.join(this.shadowManager.shadowRoot, this.app.vault.configDir);
      try {
        const lst = fs.lstatSync(symlinkPath);
        if (lst.isSymbolicLink()) fs.unlinkSync(symlinkPath);
      } catch { /* нет — ок */ }

      // 3. shadow vault recursive
      try {
        fs.rmSync(this.shadowManager.shadowRoot, { recursive: true, force: true });
      } catch (e) {
        console.error("[ShadowVault] sync rm shadow:", e);
      }

      // 4. session.lock
      const lockPath = nodePath.join(
        this.getPluginDirAbs(this.shadowManager.originalRoot),
        "session.lock"
      );
      try { fs.unlinkSync(lockPath); } catch { /* нет — ок */ }
    }

    // 5. engine.destroy через sessionManager (он держит ссылку)
    try { this.sessionManager?.destroyEngineSync(); } catch { /* ignore */ }

    this.shadowManager = null;
    this.sessionManager = null;

    console.debug("[ShadowVault] sync cleanup завершён");
  }
}
