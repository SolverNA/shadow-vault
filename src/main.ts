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
import { DataAdapter, Notice, Platform, Plugin, TAbstractFile, TFile, TFolder } from "obsidian";
import { CryptoEngine } from "./crypto-engine";
import { WebCryptoEngine } from "./web-crypto-engine";
import { DesktopAdapter, MobileAdapter, PlatformAdapter } from "./platform-adapter";
import { VirtualShadowManager } from "./virtual-shadow-manager";
import { AdapterPatcher } from "./adapter-patcher";
import { AuthResult, AuthService } from "./auth-service";
import { InitModal } from "./init-modal";
import { ShadowVaultManager } from "./shadow-vault-manager";
import { SessionManager } from "./session-manager";
import { ShadowVaultSettingTab } from "./settings-tab";
import { DEFAULT_SETTINGS, PluginSettings, VERIFICATION_PLAINTEXT, STUB_EMAIL } from "./types";
import { IDataAdapter, ListedFiles } from "./adapter-types";
import { ENCRYPTED_EXT, isTempFile } from "./fs-utils";

interface AdapterWithInternals extends IDataAdapter {
  files?: Record<string, { type: string; realpath: string; ctime?: number; mtime?: number; size?: number }>;
  trigger(event: string, ...args: unknown[]): void;
}

export default class ShadowVaultPlugin extends Plugin {
  /** Настройки плагина — читаются из data.json, записываются через saveSettings() */
  settings: PluginSettings = { ...DEFAULT_SETTINGS };

  // Модули, создаются только после успешной аутентификации
  private shadowManager:    ShadowVaultManager | null = null;
  private sessionManager:   SessionManager     | null = null;

  // Кросс-платформенные модули (v2.0.0+)
  private virtualShadowManager: VirtualShadowManager | null = null;
  private adapterPatcher: AdapterPatcher | null = null;
  private platformAdapter: PlatformAdapter | null = null;
  private cryptoEngine: CryptoEngine | WebCryptoEngine | null = null;

  /** Флаг платформы: true = десктоп (Node.js), false = мобильные (Web APIs) */
  private isDesktop = false;

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

    // Детекция платформы
    this.isDesktop = Platform.isDesktopApp;
    const isMobile = Platform.isMobile;

    console.info(`[ShadowVault] Platform: desktop=${this.isDesktop}, mobile=${isMobile}`);

    // Вкладка настроек появляется всегда, в т.ч. в спящем режиме
    this.addSettingTab(new ShadowVaultSettingTab(this.app, this));

    // Спящий режим: пользователь отключил шифрование. Плагин не вмешивается
    // в работу Obsidian — файлы в оригинале plaintext, теневое не монтируем.
    if (this.settings.encryptionDisabled) {
      console.info("[ShadowVault] encryption disabled — спящий режим");
      return;
    }

    // Подменяем adapter.list() ДО того как Obsidian построит индекс файлов.
    // Без этого при первом запуске Obsidian видит только .enc файлы и создаёт пустой индекс.
    // Ранняя подмена только транслирует имена (.enc → .md), ключ шифрования не нужен.
    this.patchListEarly();

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
    // TODO(ФАЗА 3): передавать реальный email из формы входа вместо STUB_EMAIL
    await newEngine.deriveKey(STUB_EMAIL, newPassword);

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
      verificationBlob: newVerificationBuf.toString("hex"),
    });

    newEngine.destroy();

    // 5. Блокируем — при следующем входе используется новый пароль
    await this.lockVault();
  }

  /**
   * Отключает шифрование: все файлы из shadow экспортируются как plaintext
   * в оригинал, .enc удаляются, плагин переходит в спящий режим.
   * Требует активной сессии (vault разблокирован).
   *
   * После успеха пользователю нужно перезапустить Obsidian (мы делаем
   * полный shutdown — текущий процесс продолжать с распатченным адаптером
   * без активного плагина не имеет смысла, проще попросить рестарт).
   */
  async disableEncryption(
    onProgress?: (done: number, total: number, current: string) => void
  ): Promise<void> {
    if (!this.sessionActive || !this.shadowManager) {
      throw new Error("Хранилище не разблокировано.");
    }

    console.info("[ShadowVault] disableEncryption: старт");

    // 1. Экспорт plaintext в оригинал, удаление .enc
    const result = await this.shadowManager.exportShadowToOriginal(onProgress);
    if (result.failed.length > 0) {
      throw new Error(
        `Не удалось экспортировать ${result.failed.length} файл(ов). ` +
        `См. консоль для деталей. Шифрование не отключено.`
      );
    }

    // 2. Сохраняем настройки до cleanup адаптера —
    //    если что-то упадёт ниже, флаг encryptionDisabled уже стоит
    this.settings.verificationBlob = null;
    this.settings.encryptionDisabled = true;
    await this.saveSettings();

    // 3. Снимаем mount/patch адаптера и удаляем shadow
    this.sessionActive = false;
    try {
      const adapter = this.app.vault.adapter as unknown as IDataAdapter;
      this.shadowManager.unpatch(adapter);
      this.shadowManager.unmount(adapter);
      await this.shadowManager.teardownObsidianSymlink();
    } catch (err) {
      console.error("[ShadowVault] disableEncryption: cleanup адаптера:", err);
    } finally {
      this.shadowManager = null;
    }

    try {
      await this.sessionManager?.endSession();
    } catch (err) {
      console.error("[ShadowVault] disableEncryption: endSession:", err);
    } finally {
      this.sessionManager = null;
    }

    console.info("[ShadowVault] disableEncryption: готово");
  }

  /**
   * Снимает флаг encryptionDisabled и просит перезапустить Obsidian.
   * Шифрование запустится заново при следующем onload (стандартный first-run).
   */
  async enableEncryption(): Promise<void> {
    this.settings.encryptionDisabled = false;
    await this.saveSettings();
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
    // Детекция: verificationBlob отсутствует (плагин считает что это первый
    // запуск), но в оригинале уже лежат .enc файлы. Значит data.json утерян —
    // нужно предупредить и предложить выбор: восстановить старым паролем или
    // создать новое хранилище (старые .enc станут недоступны).
    const orphanVault =
      this.settings.verificationBlob === null && this.detectEncryptedFiles();
    if (orphanVault) {
      console.warn(
        "[ShadowVault] orphan vault: .enc найдены, verificationBlob отсутствует"
      );
    }

    new InitModal(
      this.app,
      this.settings,
      (s) => this.saveSettings(s),
      (result) => { void this.onUnlock(result); },
      orphanVault
    ).open();
  }

  /**
   * Синхронно сканирует корень оригинального vault на наличие .enc файлов.
   * Используется для детекции orphan-vault — когда verificationBlob отсутствует
   * (плагин думает что это первый запуск), но .enc на диске уже есть.
   */
  private detectEncryptedFiles(): boolean {
    const basePath = this.getVaultBasePath();
    if (!basePath) return false;
    try {
      return this.scanDirForEnc(basePath, 3); // глубина 3 уровня — для скорости
    } catch {
      return false;
    }
  }

  private scanDirForEnc(absDir: string, depth: number): boolean {
    if (depth < 0) return false;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch { return false; }
    for (const e of entries) {
      if (e.name.startsWith(".")) continue;
      if (e.isFile() && e.name.endsWith(ENCRYPTED_EXT)) return true;
      if (e.isDirectory() && this.scanDirForEnc(nodePath.join(absDir, e.name), depth - 1)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Колбэк успешной аутентификации. Вызывается InitModal после
   * корректной деривации ключа и верификации пароля.
   *
   * Все операции обёрнуты в try/catch: любая ошибка инициализации
   * должна уничтожить engine и показать понятное сообщение.
   */
  private async onUnlock(result: AuthResult): Promise<void> {
    const { engine, password, isFirstRun } = result;

    // Десктопная архитектура (старая, Node.js).
    // На десктопе фабрика гарантированно вернула NodeCryptoEngine (см. AuthService).
    if (this.isDesktop) {
      await this.onUnlockDesktop(engine as CryptoEngine, isFirstRun);
      return;
    }

    // Мобильная архитектура (новая, Web APIs).
    // engine здесь — WebCryptoEngine; main.ts всё равно пересоздаёт его из пароля.
    await this.onUnlockMobile(engine, password, isFirstRun);
  }

  /**
   * Десктопная инициализация (Node.js, shadow vault на диске)
   */
  private async onUnlockDesktop(engine: CryptoEngine, isFirstRun: boolean): Promise<void> {
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
      console.info("[ShadowVault] onUnlockDesktop: старт, basePath =", basePath);

      // ── Phase 1: создаём shadow manager и initialize ──────────────────
      this.shadowManager = new ShadowVaultManager(
        engine,
        basePath,
        this.settings.shadowVaultPath || undefined,
        this.app.vault.configDir
      );
      await this.shadowManager.initialize();

      // ── Phase 2: миграция plaintext → .enc (если нужна) ───────────────
      if (await this.shadowManager.hasPendingMigration()) {
        new Notice("⏳ Shadow Vault: шифруем существующие файлы хранилища...", 5000);
        await this.shadowManager.encryptAllExisting();
        new Notice("✅ Shadow Vault: все файлы зашифрованы.", 4000);
      }

      // ── Phase 3: SessionManager + crash recovery ──────────────────────
      // recoverFromCrash шифрует правки из shadow (если они есть) обратно
      // в .enc. Это ДО reset/decrypt — иначе мы потеряли бы недосохранённые
      // изменения с прошлой сессии.
      this.sessionManager = new SessionManager(
        engine, basePath, this.shadowManager.shadowRoot, this.getPluginDirAbs(basePath)
      );
      const sessionResult = await this.sessionManager.startSession();
      if (sessionResult.hadCrash) this.notifyCrashRecovery(sessionResult.recovery!);

      // ── Phase 4: reset shadow если был краш ───────────────────────────
      // После recovery .enc актуальные. Старый shadow чистим и расшифруем
      // заново — гарантия чистого состояния, без stale-файлов и битых
      // частично-расшифрованных артефактов.
      if (sessionResult.hadCrash) {
        await this.shadowManager.resetShadow();
      }

      // ── Phase 5: восстанавливаем оригинальный list() ──────────────────
      const adapter = this.app.vault.adapter as unknown as IDataAdapter;
      if (this.earlyListOriginal) {
        adapter.list = this.earlyListOriginal;
        this.earlyListOriginal = null;
      }

      // ── Phase 6: bulk decrypt всё в shadow ────────────────────────────
      const progressNotice = new Notice("🔓 Shadow Vault: расшифровка хранилища...", 0);
      let decResult: { decrypted: string[]; failed: Array<{ path: string; error: string }> };
      try {
        decResult = await this.shadowManager.decryptAllToShadow((done, total, current) => {
          const percent = total > 0 ? Math.round((done / total) * 100) : 0;
          progressNotice.setMessage(
            `🔓 Расшифровка хранилища: ${done}/${total} (${percent}%)\n${current.slice(-60)}`
          );
        });
      } finally {
        progressNotice.hide();
      }
      if (decResult.failed.length > 0) {
        new Notice(
          `⚠️ Shadow Vault: ${decResult.failed.length} файл(ов) не удалось расшифровать. См. консоль.`,
          10000
        );
      }

      // ── Phase 7: symlink .obsidian → original/.obsidian ───────────────
      await this.shadowManager.setupObsidianSymlink();

      // ── Phase 8: MOUNT — basePath → shadowRoot ────────────────────────
      // После этой строки Obsidian работает с shadow натив но: read/write/list/
      // mkdir/rename/remove — всё через стандартный FileSystemAdapter, без
      // наших monkey-патчей. getResourcePath возвращает URL на shadow → PNG/PDF
      // открываются. fileMap синхронизируется через стандартные внутренние
      // механизмы Obsidian.
      this.shadowManager.mount(adapter);

      // ── Phase 9: reconcile fileMap (file-created для существующих) ────
      // Obsidian при первичном скане прошёл по оригиналу через patchListEarly,
      // но lstat транслированных имён фейлился (на диске .enc). Теперь файлы
      // в shadow реально существуют — толкаем file-created чтобы fileMap
      // получил TFile-объекты с актуальной мета-инфой.
      await this.reconcileVaultIndex();

      // ── Phase 10: подписки на vault events для мирроринга в .enc ──────
      this.setupVaultEventHandlers();

      // ── Phase 11: lifecycle hooks ─────────────────────────────────────
      this.registerDomEvent(window as Window, "beforeunload", () => {
        if (this.sessionActive) {
          console.info("[ShadowVault] beforeunload: sync cleanup");
          this.syncCleanup();
        }
      });

      this.sessionActive = true;

      if (isFirstRun) {
        new Notice("🔐 Shadow Vault: хранилище создано, пароль сохранён.", 5000);
      } else {
        new Notice("🔓 Shadow Vault: хранилище разблокировано.", 2500);
      }

      console.info(
        `[ShadowVault] Сессия запущена. shadowRoot=${this.shadowManager.shadowRoot}, originalRoot=${basePath}`
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

  /**
   * Мобильная инициализация (Web APIs, виртуальный shadow в памяти)
   */
  private async onUnlockMobile(engine: CryptoEngine | WebCryptoEngine, password: string, isFirstRun: boolean): Promise<void> {
    try {
      console.info("[ShadowVault] onUnlockMobile: старт");

      // ── Phase 1: создаём Web Crypto engine ────────────────────────────
      const webEngine = new WebCryptoEngine();
      // TODO(ФАЗА 3): передавать реальный email из формы входа вместо STUB_EMAIL
      await webEngine.deriveKey(STUB_EMAIL, password);
      this.cryptoEngine = webEngine;

      // Уничтожаем десктопный engine, он больше не нужен
      engine.destroy();

      // ── Phase 2: создаём platform adapter ─────────────────────────────
      this.platformAdapter = new MobileAdapter(this.app.vault);

      // ── Phase 3: создаём virtual shadow manager ───────────────────────
      this.virtualShadowManager = new VirtualShadowManager(
        webEngine,
        this.platformAdapter
      );

      // ── Phase 4: создаём adapter patcher ──────────────────────────────
      this.adapterPatcher = new AdapterPatcher(
        this.virtualShadowManager,
        this.app.vault.configDir
      );

      // ── Phase 5: патчим адаптер ───────────────────────────────────────
      const adapter = this.app.vault.adapter as DataAdapter;

      // Восстанавливаем оригинальный list() если был ранний патч
      if (this.earlyListOriginal) {
        (adapter as any).list = this.earlyListOriginal;
        this.earlyListOriginal = null;
      }

      this.adapterPatcher.patch(adapter as any);

      // ── Phase 6: reconcile fileMap ────────────────────────────────────
      await this.reconcileVaultIndex();

      // ── Phase 7: подписки на vault events ─────────────────────────────
      this.setupVaultEventHandlers();

      // ── Phase 8: lifecycle hooks ──────────────────────────────────────
      this.registerDomEvent(window as Window, "beforeunload", () => {
        if (this.sessionActive) {
          console.info("[ShadowVault] beforeunload: mobile cleanup");
          this.syncCleanupMobile();
        }
      });

      this.sessionActive = true;

      if (isFirstRun) {
        new Notice("🔐 Shadow Vault: хранилище создано, пароль сохранён.", 5000);
      } else {
        new Notice("🔓 Shadow Vault: хранилище разблокировано.", 2500);
      }

      console.info("[ShadowVault] Мобильная сессия запущена");
    } catch (err) {
      console.error("[ShadowVault] Ошибка мобильной инициализации:", err);
      new Notice(
        `❌ Shadow Vault: ошибка при запуске.\n${err instanceof Error ? err.message : String(err)}`,
        10000
      );
      this.rollbackInitialization(engine);
    }
  }

  /**
   * Подписки на vault-события: Obsidian работает в shadow натив но,
   * мы только зеркалим изменения в оригинал.enc через стандартный API.
   *
   *   create  → encryptOne (или mkdirOriginal для папок)
   *   modify  → encryptOne
   *   rename  → renameEnc (переименовать .enc; для папок — переименовать в оригинале)
   *   delete  → unlinkEnc (или rmdirOriginal для папок)
   *
   * Фильтр configDir: события для .obsidian/* игнорируем — конфиг живёт
   * через symlink, шифровать его не нужно (и Obsidian заваливал бы handler
   * каждое сохранение workspace.json).
   */
  private setupVaultEventHandlers(): void {
    const configDir = this.app.vault.configDir;
    const isConfigPath = (p: string) => p === configDir || p.startsWith(configDir + "/");

    this.registerEvent(this.app.vault.on("create", (file) => {
      if (isConfigPath(file.path)) return;
      console.debug(`[ShadowVault:event] create ${file.path}`);
      void this.handleCreate(file);
    }));

    this.registerEvent(this.app.vault.on("modify", (file) => {
      if (isConfigPath(file.path)) return;
      if (!(file instanceof TFile)) return;
      console.debug(`[ShadowVault:event] modify ${file.path}`);
      void this.shadowManager!.encryptOne(file.path).catch((err) =>
        console.error(`[ShadowVault:event] modify ${file.path} failed:`, err)
      );
    }));

    this.registerEvent(this.app.vault.on("delete", (file) => {
      if (isConfigPath(file.path)) return;
      console.debug(`[ShadowVault:event] delete ${file.path}`);
      void this.handleDelete(file);
    }));

    this.registerEvent(this.app.vault.on("rename", (file, oldPath) => {
      if (isConfigPath(file.path) || isConfigPath(oldPath)) return;
      console.debug(`[ShadowVault:event] rename ${oldPath} → ${file.path}`);
      void this.handleRename(file, oldPath);
    }));

    console.info("[ShadowVault] vault event handlers подписаны");
  }

  private async handleCreate(file: TAbstractFile): Promise<void> {
    try {
      if (file instanceof TFile) {
        await this.shadowManager!.encryptOne(file.path);
      } else if (file instanceof TFolder) {
        await this.shadowManager!.mkdirOriginal(file.path);
      }
    } catch (err) {
      console.error(`[ShadowVault:event] create ${file.path}:`, err);
    }
  }

  private async handleDelete(file: TAbstractFile): Promise<void> {
    try {
      if (file instanceof TFile) {
        await this.shadowManager!.unlinkEnc(file.path);
      } else if (file instanceof TFolder) {
        await this.shadowManager!.rmdirOriginal(file.path);
      }
    } catch (err) {
      console.error(`[ShadowVault:event] delete ${file.path}:`, err);
    }
  }

  private async handleRename(file: TAbstractFile, oldPath: string): Promise<void> {
    try {
      if (file instanceof TFile) {
        await this.shadowManager!.renameEnc(oldPath, file.path);
      } else if (file instanceof TFolder) {
        // Папка: переименовать в оригинале (там тоже структура с .enc)
        const oldOrig = nodePath.join(this.shadowManager!.originalRoot, ...oldPath.split("/"));
        const newOrig = nodePath.join(this.shadowManager!.originalRoot, ...file.path.split("/"));
        await fsp.mkdir(nodePath.dirname(newOrig), { recursive: true });
        await fsp.rename(oldOrig, newOrig);
      }
    } catch (err) {
      console.error(`[ShadowVault:event] rename ${oldPath} → ${file.path}:`, err);
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
  private rollbackInitialization(engine: CryptoEngine | WebCryptoEngine): void {
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

  /**
   * Синхронная очистка мобильной сессии (вызывается из beforeunload)
   */
  private syncCleanupMobile(): void {
    console.info("[ShadowVault] syncCleanupMobile: старт");

    this.sessionActive = false;

    // 1. Снимаем патч с адаптера
    try {
      if (this.adapterPatcher) {
        const adapter = this.app.vault.adapter as DataAdapter;
        this.adapterPatcher.unpatch(adapter as any);
      }
    } catch (err) {
      console.error("[ShadowVault] unpatch адаптера:", err);
    } finally {
      this.adapterPatcher = null;
    }

    // 2. Очищаем кэш виртуального shadow
    try {
      if (this.virtualShadowManager) {
        this.virtualShadowManager.clearCache();
      }
    } catch (err) {
      console.error("[ShadowVault] clearCache:", err);
    } finally {
      this.virtualShadowManager = null;
    }

    // 3. Уничтожаем ключ
    try {
      if (this.cryptoEngine) {
        this.cryptoEngine.destroy();
      }
    } catch (err) {
      console.error("[ShadowVault] destroy engine:", err);
    } finally {
      this.cryptoEngine = null;
    }

    this.platformAdapter = null;

    console.debug("[ShadowVault] Мобильная сессия завершена.");
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
   * Принудительно регистрирует файлы и папки в Obsidian's vault.fileMap
   * после bulk decrypt + mount. Без этого первичный скан Obsidian'а
   * не находит .md файлы (на диске только .enc, lstat фейлится),
   * vault.fileMap получает «битые» TFile-объекты, и пользователь видит
   * только папки или вообще пусто.
   *
   * Фильтр: пропускаем .obsidian и всё внутри него. Иначе adapter.trigger
   * регистрирует .obsidian как обычную пользовательскую папку в обход
   * стандартной фильтрации dotfiles → она появляется в file tree.
   */
  private async reconcileVaultIndex(): Promise<void> {
    const adapter = this.app.vault.adapter as unknown as AdapterWithInternals;
    if (typeof adapter.trigger !== "function") {
      console.warn("[ShadowVault] reconcileVaultIndex: adapter.trigger недоступен");
      return;
    }
    try {
      const stats = { folders: 0, files: 0, skipped: 0 };
      await this.notifyFilesCreated("", adapter, stats);
      console.info(
        `[ShadowVault] reconcileVaultIndex: registered ${stats.folders} folders, ` +
        `${stats.files} files, skipped ${stats.skipped}`
      );
    } catch (err) {
      console.error("[ShadowVault] reconcileVaultIndex:", err);
    }
  }

  private async notifyFilesCreated(
    dir: string,
    adapter: AdapterWithInternals,
    stats: { folders: number; files: number; skipped: number }
  ): Promise<void> {
    const configDir = this.app.vault.configDir;
    const isConfigPath = (p: string) => p === configDir || p.startsWith(configDir + "/");

    const listed = await this.app.vault.adapter.list(dir);

    // Сначала папки (vault.getDirectParent должен находить родителя для файлов)
    for (const folderPath of listed.folders) {
      if (isConfigPath(folderPath)) {
        stats.skipped++;
        continue;
      }
      if (!adapter.files?.[folderPath]) {
        adapter.files ??= {};
        adapter.files[folderPath] = { type: "folder", realpath: folderPath };
        adapter.trigger("folder-created", folderPath);
        stats.folders++;
      }
      await this.notifyFilesCreated(folderPath, adapter, stats);
    }

    for (const filePath of listed.files) {
      if (isConfigPath(filePath)) {
        stats.skipped++;
        continue;
      }
      if (adapter.files?.[filePath]) {
        // Уже зарегистрирован Obsidian'ом ранее — не дублируем
        stats.skipped++;
        continue;
      }

      // Защита от каскадных ENOENT: регистрируем файл только если он
      // ФАКТИЧЕСКИ существует в shadow (т.е. был успешно расшифрован).
      // Файлы из decryptAllToShadow.failed[] есть в .enc, но не в shadow —
      // если их зарегистрировать, любой клик пользователя приведёт к
      // ENOENT при native readFile/lstat.
      const shadowAbs = this.shadowManager!.shadowAbs(filePath);
      try {
        await fsp.access(shadowAbs);
      } catch {
        console.warn(
          `[ShadowVault] reconcile skip: "${filePath}" нет в shadow ` +
          `(decrypt failed?), не регистрируем в fileMap`
        );
        stats.skipped++;
        continue;
      }

      const s = await fsp.stat(shadowAbs).catch(() => null);
      const statObj = s
        ? {
            ctime: Math.round(s.birthtimeMs ?? s.ctimeMs),
            mtime: Math.round(s.mtimeMs),
            size: s.size,
          }
        : { ctime: Date.now(), mtime: Date.now(), size: 0 };

      adapter.files ??= {};
      adapter.files[filePath] = { type: "file", realpath: filePath, ...statObj };
      adapter.trigger("file-created", filePath, filePath, statObj);
      stats.files++;
    }
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
    if (!this.sessionActive) {
      console.debug("[ShadowVault] syncCleanup: сессия не активна, пропускаем");
      return;
    }
    this.sessionActive = false;

    const adapter = this.app.vault.adapter as unknown as IDataAdapter;
    console.info("[ShadowVault] syncCleanup: старт");

    if (this.shadowManager) {
      const shadowRoot = this.shadowManager.shadowRoot;
      const originalRoot = this.shadowManager.originalRoot;

      // 1. unpatch + unmount
      try { this.shadowManager.unpatch(adapter); console.debug("[ShadowVault] sync unpatch ok"); }
      catch (e) { console.error("[ShadowVault] sync unpatch:", e); }
      try { this.shadowManager.unmount(adapter); console.debug("[ShadowVault] sync unmount ok"); }
      catch (e) { console.error("[ShadowVault] sync unmount:", e); }

      // 2. .obsidian symlink — удаляем только если это действительно симлинк
      const symlinkPath = nodePath.join(shadowRoot, this.app.vault.configDir);
      try {
        const lst = fs.lstatSync(symlinkPath);
        if (lst.isSymbolicLink()) {
          fs.unlinkSync(symlinkPath);
          console.debug(`[ShadowVault] sync unlink symlink: ${symlinkPath}`);
        } else {
          console.warn(`[ShadowVault] sync: ${symlinkPath} не симлинк, пропускаем`);
        }
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        if (code !== "ENOENT") console.error("[ShadowVault] sync lstat .obsidian:", e);
      }

      // 3. shadow vault recursive
      try {
        fs.rmSync(shadowRoot, { recursive: true, force: true });
        console.info(`[ShadowVault] sync rm shadow ok: ${shadowRoot}`);
      } catch (e) {
        console.error(`[ShadowVault] sync rm shadow ${shadowRoot}:`, e);
      }

      // 4. session.lock
      const lockPath = nodePath.join(this.getPluginDirAbs(originalRoot), "session.lock");
      try {
        fs.unlinkSync(lockPath);
        console.debug(`[ShadowVault] sync unlink lock: ${lockPath}`);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        if (code !== "ENOENT") console.error("[ShadowVault] sync unlink lock:", e);
      }
    } else {
      console.warn("[ShadowVault] syncCleanup: shadowManager == null, нет данных для очистки");
    }

    // 5. engine.destroy через sessionManager
    try {
      this.sessionManager?.destroyEngineSync();
      console.debug("[ShadowVault] sync engine destroy ok");
    } catch (e) {
      console.error("[ShadowVault] sync engine destroy:", e);
    }

    this.shadowManager = null;
    this.sessionManager = null;

    console.info("[ShadowVault] syncCleanup: завершён");
  }
}
