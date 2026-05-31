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

import { DataAdapter, Notice, Platform, Plugin, TAbstractFile, TFile, TFolder } from "obsidian";
import { nfs, nfsp, npath } from "./node-fs";
import { CryptoEngine } from "./crypto-engine";
import { WebCryptoEngine } from "./web-crypto-engine";
import { MobileAdapter, PlatformAdapter } from "./platform-adapter";
import { VirtualShadowManager } from "./virtual-shadow-manager";
import { AdapterPatcher } from "./adapter-patcher";
import { AuthResult, AuthService } from "./auth-service";
import { InitModal } from "./init-modal";
import { PinStore } from "./pin-store";
import { deriveMasterKey } from "./crypto/key-derivation";
import { FORMAT_VERSION } from "./crypto/constants";
// Desktop-only модули грузятся ЛЕНИВО (await import) только в desktop-ветке
// onUnlockDesktop — их top-level node-импорты не должны выполняться на mobile.
import type { ShadowVaultManager } from "./shadow-vault-manager";
import type { SessionManager } from "./session-manager";
import { ShadowVaultSettingTab } from "./settings-tab";
import { DEFAULT_SETTINGS, PluginSettings, VERIFICATION_PLAINTEXT } from "./types";
import { IDataAdapter, ListedFiles } from "./adapter-types";
import { ENCRYPTED_EXT, listEncryptedDir } from "./fs-utils";
import { bytesToHex } from "./hex";
import { Logger, LogLevel, LogAdapter } from "./logger";
import { BugReporter, VaultStats } from "./bug-report";
import { DiagnosticsController } from "./diagnostics-controller";

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

  /** Подробное логирование (debug + ротация в каталог плагина). */
  logger!: Logger;
  /** Обязательный баг-репорт при любой пойманной ошибке ключевых операций. */
  bugReporter!: BugReporter;
  /** Подписки на window error/unhandledrejection (снимаются в onunload). */
  private globalErrorHandlers: Array<() => void> = [];

  /**
   * Контроллер диагностики: централизованная обработка ошибок ключевых
   * операций + дедупликация баг-репортов. Создаётся в initDiagnostics после
   * Logger/BugReporter. Публичный plugin.reportError делегирует сюда.
   */
  private diagnostics!: DiagnosticsController;

  /** true только пока сессия активна (между onUnlock и shutdown) */
  private sessionActive = false;

  /**
   * true с момента входа в shutdown()/onunload до полного завершения.
   * Гейт для vault-обработчиков: пока флаг взведён, менеджер вот-вот будет
   * (или уже) обнулён — события Obsidian, прилетевшие «в полёте» (autosave/flush
   * при закрытии), безопасно игнорируются, чтобы не дереференсить null.
   * Выставляется ДО обнуления shadowManager, но ПОСЛЕ того как drain/encrypt-back
   * уже захватили все ранее зарегистрированные правки.
   */
  private shuttingDown = false;

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

    // Диагностика (логгер + баг-репортер) инициализируется ПЕРВОЙ —
    // чтобы зафиксировать весь жизненный цикл, включая спящий режим и ошибки.
    this.initDiagnostics();
    this.logger.info("main", "onload: старт", {
      desktop: this.isDesktop,
      mobile: isMobile,
      pluginVersion: this.manifest.version,
    });

    // Вкладка настроек появляется всегда, в т.ч. в спящем режиме
    this.addSettingTab(new ShadowVaultSettingTab(this.app, this));

    // Спящий режим: пользователь отключил шифрование. Плагин не вмешивается
    // в работу Obsidian — файлы в оригинале plaintext, теневое не монтируем.
    if (this.settings.encryptionDisabled) {
      this.logger.info("main", "encryption disabled — спящий режим");
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

    this.logger.debug("main", "onload: завершён, ожидаем пароль");
  }

  onunload(): void {
    // Взводим гейт первым делом: при закрытии Obsidian шлёт flush/autosave
    // события «в полёте» — обработчики должны их игнорировать, а не
    // дереференсить обнуляемый shadowManager.
    this.shuttingDown = true;
    this.logger?.info("main", "onunload: старт", { sessionActive: this.sessionActive });
    // Снимаем глобальные обработчики ошибок.
    for (const off of this.globalErrorHandlers) {
      try { off(); } catch { /* ignore */ }
    }
    this.globalErrorHandlers = [];
    // Obsidian закрывается агрессивно и НЕ ждёт async-shutdown — поэтому
    // используем sync-версию очистки. Write-through уже сохранил все
    // изменения в оригинал на каждый save, на shutdown остаётся только
    // удалить shadow и lock — это всё делается синхронно через fs.*Sync.
    if (this.sessionActive) {
      // Разводим очистку по платформе: desktop удаляет реальный shadow через
      // fs.*Sync, mobile снимает патч и чистит in-memory кэш (без node:fs).
      if (this.isDesktop) {
        this.syncCleanup();
      } else {
        this.syncCleanupMobile();
      }
    }
    // Финальный флаш логов (best-effort, async — Obsidian не ждёт).
    void this.logger?.close();
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Диагностика: логгер + обязательный баг-репорт
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Инициализирует логгер и баг-репортер. Запись идёт через Obsidian adapter
   * (кросс-платформенно desktop+mobile), без top-level node:fs. Каталоги —
   * внутри папки данных плагина: <configDir>/plugins/<id>/{logs,bug-reports}.
   */
  private initDiagnostics(): void {
    const adapter = this.app.vault.adapter as unknown as LogAdapter;
    const pluginDir = `${this.app.vault.configDir}/plugins/${this.manifest.id}`;
    const logDir = `${pluginDir}/logs`;
    const reportDir = `${pluginDir}/bug-reports`;

    // По умолчанию подробное логирование (пользователь просил «подробнейшее»).
    const minLevel = LogLevel.DEBUG;

    this.logger = new Logger(adapter, {
      logDir,
      minLevel,
      ringSize: 1500,
      maxFileBytes: 512 * 1024,
      maxFiles: 3,
      flushIntervalMs: 1500,
      mirrorConsole: true,
    });

    this.bugReporter = new BugReporter(
      adapter,
      reportDir,
      {
        pluginVersion: this.manifest.version,
        platform: this.isDesktop ? "desktop" : "mobile",
        isDesktop: this.isDesktop,
        obsidianVersion: this.getObsidianVersion(),
      },
      () => this.logger.tail(200),
    );

    // Контроллер диагностики получает узкий контекст (НЕ весь Plugin):
    // логгер, баг-репортер, колбэк сбора статистик и колбэк показа Notice.
    this.diagnostics = new DiagnosticsController({
      logger: this.logger,
      bugReporter: this.bugReporter,
      collectStats: () => this.collectVaultStats().catch(() => undefined),
      showNotice: (message, timeoutMs) => { new Notice(message, timeoutMs); },
    });

    // Глобальные перехватчики — пока плагин активен. Не роняем приложение,
    // лишь логируем и пишем баг-репорт. Отписка в onunload.
    const onError = (ev: ErrorEvent) => {
      void this.reportError("window.error", ev.error ?? new Error(ev.message), {
        filename: ev.filename,
        lineno: ev.lineno,
      }, { silent: true });
    };
    const onRejection = (ev: PromiseRejectionEvent) => {
      void this.reportError("window.unhandledrejection", ev.reason, undefined, { silent: true });
    };
    try {
      window.addEventListener("error", onError);
      window.addEventListener("unhandledrejection", onRejection);
      this.globalErrorHandlers.push(
        () => window.removeEventListener("error", onError),
        () => window.removeEventListener("unhandledrejection", onRejection),
      );
    } catch { /* среды без window (тесты) — пропускаем */ }
  }

  /** Версия Obsidian, если доступна через глобальный apiVersion. */
  private getObsidianVersion(): string | undefined {
    try {
      const g = globalThis as unknown as { apiVersion?: string };
      return g.apiVersion;
    } catch {
      return undefined;
    }
  }

  /**
   * Централизованный обработчик ошибок ключевых операций: (а) логирует error,
   * (б) пишет баг-репорт в каталог плагина, (в) показывает пользователю Notice
   * с путём к репорту. Не глотает данные и не роняет приложение молча.
   *
   * @returns путь к сохранённому баг-репорту (или null).
   */
  async reportError(
    operation: string,
    error: unknown,
    context?: Record<string, unknown>,
    opts?: { silent?: boolean },
  ): Promise<string | null> {
    // Тонкая обёртка: вся логика (лог + дедуп + баг-репорт + Notice) в
    // DiagnosticsController. main отвечает лишь за жизненный цикл.
    return this.diagnostics.reportError(operation, error, context, opts);
  }

  /**
   * Безопасные статистики хранилища для баг-репорта: только числа, без
   * содержимого файлов. Считаем .enc в корне оригинала (поверхностно).
   */
  private async collectVaultStats(): Promise<VaultStats> {
    const stats: VaultStats = { formatVersion: this.settings.formatVersion };
    try {
      const adapter = this.app.vault.adapter as unknown as IDataAdapter;
      const configDir = this.app.vault.configDir;
      const listed = await adapter.list("");
      let total = 0;
      let enc = 0;
      let bytes = 0;
      for (const f of listed.files) {
        if (f === configDir || f.startsWith(configDir + "/")) continue;
        total++;
        if (f.endsWith(ENCRYPTED_EXT)) enc++;
        const st = await adapter.stat(f).catch(() => null);
        if (st?.size) bytes += st.size;
      }
      stats.totalFiles = total;
      stats.encFiles = enc;
      stats.totalBytes = bytes;
    } catch { /* статистика опциональна */ }
    return stats;
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
   * Меняет пароль хранилища (обратная совместимость / тонкая обёртка).
   * Email не меняется. См. changeCredentials.
   */
  async changePassword(
    oldPassword: string,
    newPassword: string,
    onProgress: (done: number, total: number) => void
  ): Promise<void> {
    await this.changeCredentials(oldPassword, this.settings.email, newPassword, onProgress);
  }

  /**
   * ОБЪЕДИНЁННАЯ смена учётных данных: email и/или пароль за ОДНУ
   * пере-шифровку. Смена email меняет соль (salt = SHA-256(email‖domain)),
   * смена пароля меняет KDF-вход — в обоих случаях это новый masterKey, т.е.
   * один и тот же процесс: пере-шифровать всё хранилище новым ключом.
   *
   * Шаги:
   *   1. Проверить ТЕКУЩИЙ пароль через verifyPassword (текущий email+пароль)
   *      ДО любых разрушительных операций. Неверный → PasswordError, ничего
   *      не тронуто.
   *   2. Вычислить НОВЫЙ ключ из (newEmail, newPassword).
   *   3. Пере-шифровать ВСЁ хранилище новым ключом (desktop: двухфазно
   *      атомарно через .enc.new→.enc; mobile: пофайлово с round-trip verify).
   *   4. Только после полного успеха: обновить data.json (email,
   *      verificationBlob новым ключом), СБРОСИТЬ PIN, заблокировать.
   *
   * Хотя бы одно из (email, пароль) должно отличаться — проверяет вызывающий UI.
   *
   * @throws PasswordError если текущий пароль неверный
   */
  async changeCredentials(
    oldPassword: string,
    newEmail: string,
    newPassword: string,
    onProgress: (done: number, total: number) => void
  ): Promise<void> {
    if (!this.sessionActive) {
      throw new Error("Хранилище не разблокировано.");
    }

    const oldEmail = this.settings.email;
    const targetEmail = (newEmail || oldEmail).trim();
    const targetPassword = newPassword || oldPassword;

    this.logger.info("credentials", "смена учётных данных: старт", {
      emailChanged: targetEmail !== oldEmail,
      desktop: this.isDesktop,
    });

    // 1. Верифицируем ТЕКУЩИЙ пароль (старый email + старый пароль) независимо
    //    от активной сессии — защита от смены на разблокированном чужом
    //    устройстве. До этой точки ничего не меняем.
    const checkEngine = await AuthService.verifyPassword(oldEmail, oldPassword, this.settings);
    checkEngine.destroy();

    if (this.isDesktop) {
      // 2. Новый desktop-движок с НОВЫМ ключом (новый email и/или пароль).
      const newEngine = new CryptoEngine();
      await newEngine.deriveKey(targetEmail, targetPassword);

      // 3. Пере-шифровка всех .enc (двухфазно, атомарно: .enc.new → .enc).
      try {
        if (!this.shadowManager) {
          throw new Error("shadowManager не инициализирован — сессия не активна");
        }
        await this.shadowManager.reEncryptAll(newEngine, (done, total) => {
          if (total > 0 && (done === total || done % 25 === 0)) {
            this.logger.debug("reEncrypt", "прогресс (desktop)", { done, total });
          }
          onProgress(done, total);
        });
      } catch (err) {
        newEngine.destroy();
        await this.reportError("reEncrypt.desktop", err);
        throw err;
      }

      // 4. Настройки — только после полного успеха пере-шифровки.
      const newVerificationBuf = newEngine.encryptBuffer(
        Buffer.from(VERIFICATION_PLAINTEXT, "utf8")
      );
      await this.saveSettings({
        ...this.settings,
        email: targetEmail,
        verificationBlob: bytesToHex(newVerificationBuf),
      });
      newEngine.destroy();
    } else {
      // ── Mobile-путь: WebCryptoEngine + VirtualShadowManager ──────────────
      const newEngine = new WebCryptoEngine();
      await newEngine.deriveKey(targetEmail, targetPassword);

      try {
        if (!this.virtualShadowManager) {
          throw new Error("virtualShadowManager не инициализирован — сессия не активна");
        }
        await this.virtualShadowManager.reEncryptAll(
          this.app.vault.configDir,
          newEngine,
          onProgress
        );
      } catch (err) {
        await this.reportError("reEncrypt.mobile", err);
        throw err;
      }

      const blob = await newEngine.encryptBuffer(
        new TextEncoder().encode(VERIFICATION_PLAINTEXT)
      );
      await this.saveSettings({
        ...this.settings,
        email: targetEmail,
        verificationBlob: bytesToHex(new Uint8Array(blob)),
      });
      // Активный движок плагина переключаем на новый ключ.
      this.cryptoEngine = newEngine;
    }

    // PIN привязан к старому masterKey → после смены ключа он невалиден.
    new PinStore().clearPin();

    this.logger.info("credentials", "смена учётных данных завершена");

    // Блокируем — при следующем входе используется новый email/пароль.
    await this.lockVault();
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PIN — быстрый локальный вход (device-local key-wrapping)
  // ═══════════════════════════════════════════════════════════════════════

  /** true, если на этом устройстве настроен PIN-вход. */
  isPinEnabled(): boolean {
    return new PinStore().isPinSet();
  }

  /**
   * Задаёт/меняет PIN. Требует подтверждения пароля: из него re-деривируется
   * masterKey, который оборачивается ключом из PIN и сохраняется ЛОКАЛЬНО
   * (window.localStorage) — НИКОГДА в data.json/синхронизируемые файлы.
   *
   * @throws PasswordError если пароль неверный
   */
  async setupPin(password: string, pin: string): Promise<void> {
    if (!/^\d{4,8}$/.test(pin)) {
      throw new Error("PIN должен состоять из 4–8 цифр.");
    }
    const email = this.settings.email;
    // Проверяем пароль через verificationBlob (бросит PasswordError при ошибке).
    const checkEngine = await AuthService.verifyPassword(email, password, this.settings);
    checkEngine.destroy();

    // Re-деривируем сырой мастер-ключ и оборачиваем его PIN-ключом.
    const masterKey = await deriveMasterKey(email, password);
    try {
      await new PinStore().enablePin(pin, masterKey);
      this.logger.info("pin", "PIN установлен");
    } catch (err) {
      await this.reportError("pin.setup", err);
      throw err;
    } finally {
      masterKey.fill(0);
    }
  }

  /** Удаляет PIN-данные с устройства. */
  removePin(): void {
    new PinStore().clearPin();
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
    // Шифрование отключено → PIN больше не нужен и невалиден.
    new PinStore().clearPin();

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
    const fs = nfs();
    let entries: import("fs").Dirent[];
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch { return false; }
    for (const e of entries) {
      if (e.name.startsWith(".")) continue;
      if (e.isFile() && e.name.endsWith(ENCRYPTED_EXT)) return true;
      if (e.isDirectory() && this.scanDirForEnc(npath().join(absDir, e.name), depth - 1)) {
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
    const { engine, password, email, rawKey, isFirstRun } = result;

    // Десктопная архитектура (старая, Node.js).
    // На десктопе фабрика гарантированно вернула NodeCryptoEngine (см. AuthService).
    if (this.isDesktop) {
      await this.onUnlockDesktop(engine as CryptoEngine, isFirstRun, password);
      return;
    }

    // Мобильная архитектура (новая, Web APIs).
    // engine здесь — WebCryptoEngine; main.ts пересоздаёт его из email+password
    // (обычный вход) либо из сырого мастер-ключа (вход по PIN).
    await this.onUnlockMobile(engine, { password, email, rawKey }, isFirstRun);
  }

  /**
   * Десктопная инициализация (Node.js, shadow vault на диске)
   */
  private async onUnlockDesktop(
    engine: CryptoEngine,
    isFirstRun: boolean,
    password: string | null
  ): Promise<void> {
    const basePath = this.getVaultBasePath();
    if (!basePath) {
      new Notice(
        "❌ Shadow Vault: getBasePath() недоступен, плагин работает только на десктопе.",
        10000
      );
      engine.destroy();
      return;
    }

    const t0 = Date.now();
    try {
      this.logger.info("unlock", "onUnlockDesktop: старт", { firstRun: isFirstRun, viaPin: password === null, basePath });

      // Ленивая загрузка desktop-only модулей. Их top-level node-импорты
      // выполнятся только здесь (Node runtime гарантирован), на mobile этот
      // код недостижим — бандл не вычисляет fs/path/os при загрузке.
      const { ShadowVaultManager } = await import("./shadow-vault-manager");
      const { SessionManager } = await import("./session-manager");

      // ── Phase 1: создаём shadow manager и initialize ──────────────────
      // Путь к теневому хранилищу больше НЕ пользовательская настройка:
      // всегда undefined → детерминированное авто-вычисление по хешу basePath.
      this.shadowManager = new ShadowVaultManager(
        engine,
        basePath,
        undefined,
        this.app.vault.configDir,
        this.logger
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
        engine, basePath, this.shadowManager.shadowRoot, this.getPluginDirAbs(basePath), this.logger
      );
      const sessionResult = await this.sessionManager.startSession();
      this.logger.info("recovery", "startSession", { hadCrash: sessionResult.hadCrash });
      if (sessionResult.hadCrash) {
        const rec = sessionResult.recovery!;
        this.logger.warn("recovery", "обнаружен краш прошлой сессии", {
          recovered: rec.recoveredFiles.length,
          failed: rec.failedFiles.length,
          corruptedShadow: rec.corruptedShadow.length,
        });
        this.notifyCrashRecovery(rec);
      }

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

      // ── Phase 5.5: миграция legacy → v2 (ФАЗА 4) ──────────────────────
      // Старые .enc (формат до v2) надо перешифровать новым v2-ключом ДО
      // bulk-decrypt: decryptAllToShadow умеет читать только v2.
      // Делаем это после проверки пароля (см. ниже probe) и пофайлово атомарно.
      await this.migrateLegacyIfNeeded(password);

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
      this.logger.info("decrypt", "decryptAllToShadow завершён", {
        decrypted: decResult.decrypted.length,
        failed: decResult.failed.length,
      });
      if (decResult.failed.length > 0) {
        this.logger.warn("decrypt", "часть файлов не расшифрована", {
          failedPaths: decResult.failed.map((f) => f.path),
        });
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

      this.shuttingDown = false;
      this.sessionActive = true;

      if (isFirstRun) {
        new Notice("🔐 Shadow Vault: хранилище создано, пароль сохранён.", 5000);
      } else {
        new Notice("🔓 Shadow Vault: хранилище разблокировано.", 2500);
      }

      this.logger.info("unlock", "desktop-сессия запущена", {
        ms: Date.now() - t0,
        shadowRoot: this.shadowManager.shadowRoot,
        originalRoot: basePath,
      });
    } catch (err) {
      await this.reportError("unlock.desktop", err, { firstRun: isFirstRun, ms: Date.now() - t0 });
      new Notice(
        `❌ Shadow Vault: ошибка при запуске.\n${err instanceof Error ? err.message : String(err)}`,
        10000
      );
      await this.rollbackInitialization(engine);
    }
  }

  /**
   * ФАЗА 4: миграция legacy → v2 на десктопе.
   *
   * Вызывается из onUnlockDesktop ПЕРЕД bulk-decrypt. Шаги:
   *   1. Если formatVersion уже 2 И legacy-файлов нет — быстрый выход.
   *   2. Если password == null (вход по PIN) — миграцию по паролю сделать
   *      нельзя; легаси на этом этапе быть не должно (PIN ставится только
   *      после первого парольного входа). Если вдруг есть — предупреждаем.
   *   3. Проверяем пароль через trial-decrypt первого .enc (для legacy-хранилищ
   *      без verificationBlob это единственная проверка). Неверный → ошибка,
   *      разрушительных операций НЕ начинаем.
   *   4. Мигрируем пофайлово атомарно. После успеха помечаем formatVersion=2 и
   *      гарантируем наличие v2 verificationBlob.
   */
  private async migrateLegacyIfNeeded(password: string | null): Promise<void> {
    if (!this.shadowManager) return;
    const { probeLegacyPassword } = await import("./crypto/migration");

    const hasLegacy = await this.shadowManager.hasLegacyFiles();
    this.logger.debug("migration", "проверка legacy (desktop)", { hasLegacy, viaPin: password === null });

    // Гарантируем verificationBlob даже для пустых/уже-v2 legacy-хранилищ:
    // старые data.json его не имеют. Если blob уже есть (AuthService создал
    // на "первом запуске") — ничего не делаем.
    if (!hasLegacy) {
      if (this.settings.formatVersion !== FORMAT_VERSION) {
        this.settings.formatVersion = FORMAT_VERSION;
        await this.saveSettings();
      }
      // Самовосстановление блоба для v2-хранилища без verificationBlob.
      // ВАЖНО: блоб создаём ТОЛЬКО после проверки пароля по реальному v2-файлу.
      // Иначе неверный пароль создал бы «валидный» блоб для НЕВЕРНОГО ключа и
      // навсегда сломал бы вход (точно этот баг и наблюдался у пользователя).
      await this.recoverVerificationBlobDesktop(password);
      return;
    }

    if (password === null) {
      // Вход по PIN над legacy-хранилищем — нештатно. Не трогаем файлы.
      new Notice(
        "⚠️ Shadow Vault: обнаружены файлы старого формата, но вход выполнен по PIN. " +
        "Войдите паролем, чтобы выполнить миграцию.",
        10000
      );
      return;
    }

    // ── Проверка пароля через trial-decrypt первого legacy-файла ──────────
    // hasLegacy уже true: ищем первый РЕАЛЬНЫЙ legacy-образец (v2/пустые
    // firstEncBuffer мог бы вернуть — поэтому пробуем все, пока не получим
    // явный legacy-исход).
    const encFiles = await this.shadowManager.scanEncryptedFiles();
    let decided = false;
    for (const rel of encFiles) {
      let sample: Uint8Array;
      try {
        sample = new Uint8Array(await this.shadowManager.readEncFull(rel));
      } catch {
        continue;
      }
      const probe = await probeLegacyPassword(sample, password);
      if (probe.status === "NOT_LEGACY") continue; // v2/пустой — не образец для проверки
      decided = true;
      this.logger.info("auth", "проверка legacy-пароля (desktop)", { success: probe.status === "LEGACY_OK" });
      if (probe.status === "LEGACY_WRONG_PASSWORD") {
        // ТОЛЬКО реальный legacy-файл, который не дешифруется → неверный пароль.
        // НЕ трогаем verificationBlob (если он валиден для v2-файлов — он нужен).
        throw new Error(
          "Неверный пароль для хранилища старого формата — миграция отменена, файлы не тронуты."
        );
      }
      break; // LEGACY_OK — пароль верный, идём мигрировать
    }
    if (!decided) {
      this.logger.warn("auth", "legacy-проверка: образцов legacy не найдено (все v2/пустые)");
    }

    // ── Миграция пофайлово, атомарно, с прогрессом ────────────────────────
    const migNotice = new Notice("🔄 Shadow Vault: миграция хранилища в новый формат...", 0);
    let result;
    try {
      result = await this.shadowManager.migrateLegacyToV2(password, (done, total, current) => {
        const percent = total > 0 ? Math.round((done / total) * 100) : 0;
        migNotice.setMessage(`🔄 Миграция формата: ${done}/${total} (${percent}%)\n${current.slice(-60)}`);
      });
    } finally {
      migNotice.hide();
    }

    this.logger.info("migration", "миграция legacy→v2 (desktop) завершена", {
      migrated: result.migrated.length,
      failed: result.failed.length,
    });
    if (result.failed.length > 0) {
      this.logger.warn("migration", "часть файлов не мигрирована", {
        failedPaths: result.failed.map((f) => (typeof f === "string" ? f : f.path)),
      });
      new Notice(
        `⚠️ Shadow Vault: ${result.failed.length} файл(ов) не мигрировано (см. консоль). ` +
        "Остальные переведены в новый формат.",
        10000
      );
    } else {
      new Notice(`✅ Shadow Vault: миграция завершена (${result.migrated.length} файлов).`, 4000);
    }

    // formatVersion обновляем ТОЛЬКО если миграция прошла без ошибок —
    // иначе при следующем входе снова просканируем и домигрируем остаток.
    if (result.failed.length === 0) {
      this.settings.formatVersion = FORMAT_VERSION;
      await this.saveSettings();
    }
    // Verification blob для нового v2-ключа (если ещё не создан AuthService'ом).
    await this.ensureVerificationBlobDesktop();
  }

  /**
   * Гарантирует наличие v2 verificationBlob в настройках. Шифрует маркер
   * текущим v2-движком. Вызывается ПОСЛЕ того, как ключ уже доказанно верен
   * (успешная legacy-миграция). Для случая «v2-хранилище без блоба» использовать
   * recoverVerificationBlobDesktop (там пароль ещё надо проверить).
   */
  private async ensureVerificationBlobDesktop(): Promise<void> {
    if (this.settings.verificationBlob || !this.shadowManager) return;
    try {
      const engine = this.shadowManager.getEngine();
      const blob = engine.encryptBuffer(Buffer.from(VERIFICATION_PLAINTEXT, "utf8"));
      this.settings.verificationBlob = Buffer.from(blob).toString("hex");
      this.settings.formatVersion = FORMAT_VERSION;
      await this.saveSettings();
      console.info("[ShadowVault] Создан v2 verificationBlob.");
    } catch (err) {
      console.error("[ShadowVault] Не удалось создать verificationBlob:", err);
    }
  }

  /**
   * Самовосстановление verificationBlob для v2-хранилища без блоба (desktop).
   *
   * Сценарий: data.json потерян/повреждён (verificationBlob=null), но .enc
   * уже в формате v2. AuthService счёл это «первым запуском» и НЕ проверил
   * пароль. Здесь мы:
   *   1. Если блоб уже есть — ничего не делаем (verifyPassword отработал ранее).
   *   2. Пытаемся расшифровать первый ВАЛИДНЫЙ v2 .enc текущим ключом:
   *        - успех  → пароль верный → создаём блоб заново и сохраняем;
   *        - провал → это РЕАЛЬНО неверный пароль → бросаем ошибку, .enc и блоб
   *                   НЕ трогаем (данные целы);
   *        - валидных v2-файлов нет (пустое/новое хранилище) → first-run-подобный
   *          случай: создаём блоб текущим ключом и продолжаем.
   */
  private async recoverVerificationBlobDesktop(password: string | null): Promise<void> {
    if (this.settings.verificationBlob || !this.shadowManager) return;

    const valid = await this.shadowManager.validateV2Password();
    this.logger.info("auth", "самовосстановление блоба (desktop)", {
      v2Check: valid === null ? "no-v2-files" : valid ? "ok" : "wrong-password",
      viaPin: password === null,
    });

    if (valid === false) {
      // Реальный v2-файл не расшифровался текущим ключом → неверный пароль.
      // Ничего не трогаем: .enc целы, блоб не создаём.
      throw new Error("Неверный пароль для хранилища.");
    }
    // valid === true (пароль верен) ИЛИ valid === null (нет v2-файлов, новое
    // хранилище) → создаём блоб текущим (проверенным/новым) ключом.
    await this.ensureVerificationBlobDesktop();
  }

  /**
   * Мобильная инициализация (Web APIs, виртуальный shadow в памяти)
   */
  private async onUnlockMobile(
    engine: CryptoEngine | WebCryptoEngine,
    creds: { password: string | null; email: string; rawKey?: Uint8Array },
    isFirstRun: boolean
  ): Promise<void> {
    const t0 = Date.now();
    try {
      this.logger.info("unlock", "onUnlockMobile: старт", { firstRun: isFirstRun, viaPin: !!creds.rawKey });

      // ── Phase 1: создаём Web Crypto engine ────────────────────────────
      const webEngine = new WebCryptoEngine();
      if (creds.rawKey) {
        // Вход по PIN: загружаем уже развёрнутый мастер-ключ напрямую.
        await webEngine.loadRawKey(creds.rawKey);
      } else {
        // Обычный вход: деривируем ключ из email + пароля.
        await webEngine.deriveKey(creds.email, creds.password ?? "");
      }
      this.cryptoEngine = webEngine;

      // Уничтожаем десктопный engine, он больше не нужен
      engine.destroy();

      // ── Phase 2: создаём platform adapter ─────────────────────────────
      this.platformAdapter = new MobileAdapter(this.app.vault);

      // ── Phase 3: создаём virtual shadow manager ───────────────────────
      this.virtualShadowManager = new VirtualShadowManager(
        webEngine,
        this.platformAdapter,
        this.logger
      );

      // ── Phase 3.5: миграция legacy → v2 (ФАЗА 4) ──────────────────────
      // До патча адаптера: после миграции все .enc в формате v2 и
      // VirtualShadowManager.read сможет их расшифровать.
      await this.migrateLegacyMobileIfNeeded(creds.password);

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

      this.shuttingDown = false;
      this.sessionActive = true;

      if (isFirstRun) {
        new Notice("🔐 Shadow Vault: хранилище создано, пароль сохранён.", 5000);
      } else {
        new Notice("🔓 Shadow Vault: хранилище разблокировано.", 2500);
      }

      this.logger.info("unlock", "mobile-сессия запущена", { ms: Date.now() - t0 });
    } catch (err) {
      await this.reportError("unlock.mobile", err, { firstRun: isFirstRun, ms: Date.now() - t0 });
      new Notice(
        `❌ Shadow Vault: ошибка при запуске.\n${err instanceof Error ? err.message : String(err)}`,
        10000
      );
      await this.rollbackInitialization(engine);
    }
  }

  /**
   * ФАЗА 4: миграция legacy → v2 на mobile (последовательно через Vault API).
   * Зеркалит логику десктопа: probe пароля → миграция → formatVersion/блоб.
   */
  private async migrateLegacyMobileIfNeeded(password: string | null): Promise<void> {
    const vsm = this.virtualShadowManager;
    if (!vsm) return;
    const configDir = this.app.vault.configDir;

    const hasLegacy = await vsm.hasLegacyFiles(configDir);
    this.logger.debug("migration", "проверка legacy (mobile)", { hasLegacy, viaPin: password === null });
    if (!hasLegacy) {
      if (this.settings.formatVersion !== FORMAT_VERSION) {
        this.settings.formatVersion = FORMAT_VERSION;
        await this.saveSettings();
      }
      // Самовосстановление блоба для v2-хранилища без verificationBlob (mobile).
      // Блоб создаётся ТОЛЬКО после проверки пароля по реальному v2-файлу.
      await this.recoverVerificationBlobMobile(configDir, password);
      return;
    }

    if (password === null) {
      new Notice(
        "⚠️ Shadow Vault: обнаружены файлы старого формата, но вход выполнен по PIN. " +
        "Войдите паролем, чтобы выполнить миграцию.",
        10000
      );
      return;
    }

    // Проверка пароля через trial-decrypt (хранилище без verificationBlob).
    const probe = await vsm.probePassword(configDir, password);
    this.logger.info("auth", "проверка legacy-пароля (mobile)", { status: probe });
    if (probe === "LEGACY_WRONG_PASSWORD") {
      // ТОЛЬКО реальный legacy-файл не дешифровался → неверный пароль.
      // verificationBlob НЕ трогаем.
      throw new Error(
        "Неверный пароль для хранилища старого формата — миграция отменена, файлы не тронуты."
      );
    }
    // probe === "NOT_LEGACY" (несмотря на hasLegacy: маловероятно, но безопасно)
    // или "LEGACY_OK" → продолжаем миграцию.

    const migNotice = new Notice("🔄 Shadow Vault: миграция хранилища в новый формат...", 0);
    let result;
    try {
      result = await vsm.migrateLegacyToV2(configDir, password, (done, total, current) => {
        const percent = total > 0 ? Math.round((done / total) * 100) : 0;
        migNotice.setMessage(`🔄 Миграция формата: ${done}/${total} (${percent}%)\n${current.slice(-60)}`);
      });
    } finally {
      migNotice.hide();
    }

    this.logger.info("migration", "миграция legacy→v2 (mobile) завершена", {
      migrated: result.migrated,
      skipped: result.skipped,
      failed: result.failed.length,
    });
    if (result.failed.length > 0) {
      this.logger.warn("migration", "часть файлов не мигрирована (mobile)", {
        failedPaths: result.failed.map((f) => f.path),
      });
      new Notice(
        `⚠️ Shadow Vault: ${result.failed.length} файл(ов) не мигрировано (см. консоль).`,
        10000
      );
    } else {
      new Notice(`✅ Shadow Vault: миграция завершена (${result.migrated} файлов).`, 4000);
      this.settings.formatVersion = FORMAT_VERSION;
      await this.saveSettings();
    }
    await this.ensureVerificationBlobMobile();
  }

  /**
   * Самовосстановление verificationBlob для v2-хранилища без блоба (mobile).
   * Зеркалит recoverVerificationBlobDesktop: проверяет пароль по реальному v2
   * .enc через VirtualShadowManager.validateV2Password, и только при успехе
   * (или отсутствии v2-файлов) создаёт блоб.
   */
  private async recoverVerificationBlobMobile(
    configDir: string,
    password: string | null
  ): Promise<void> {
    if (this.settings.verificationBlob) return;
    const vsm = this.virtualShadowManager;
    if (!vsm) return;

    const valid = await vsm.validateV2Password(configDir);
    this.logger.info("auth", "самовосстановление блоба (mobile)", {
      v2Check: valid === null ? "no-v2-files" : valid ? "ok" : "wrong-password",
      viaPin: password === null,
    });

    if (valid === false) {
      throw new Error("Неверный пароль для хранилища.");
    }
    await this.ensureVerificationBlobMobile();
  }

  /**
   * Гарантирует наличие v2 verificationBlob на mobile (WebCryptoEngine async).
   */
  private async ensureVerificationBlobMobile(): Promise<void> {
    if (this.settings.verificationBlob) return;
    const engine = this.cryptoEngine;
    if (!engine) return;
    try {
      const blob = await Promise.resolve(
        engine.encryptBuffer(new TextEncoder().encode(VERIFICATION_PLAINTEXT))
      );
      const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob as ArrayBuffer);
      this.settings.verificationBlob = bytesToHex(bytes);
      this.settings.formatVersion = FORMAT_VERSION;
      await this.saveSettings();
      console.info("[ShadowVault] Создан v2 verificationBlob (mobile) для legacy-хранилища.");
    } catch (err) {
      console.error("[ShadowVault] Не удалось создать verificationBlob (mobile):", err);
    }
  }

  /**
   * Разводит подписку на vault-события по платформе.
   *
   * DESKTOP: Obsidian работает в реальном shadow на диске; мы зеркалим
   *   каждое изменение в оригинал.enc через ShadowVaultManager (write-through
   *   поверх vault-событий).
   *
   * MOBILE: shadow виртуальный; write-through уже выполняет AdapterPatcher
   *   на уровне adapter.read/write/remove/rename/copy (события Obsidian
   *   приходят ПОСЛЕ завершения этих операций). Поэтому на mobile НЕ дёргаем
   *   desktop-only shadowManager (его нет — был бы TypeError), достаточно
   *   лёгких обработчиков для логирования/папок.
   */
  private setupVaultEventHandlers(): void {
    if (this.isDesktop) {
      this.setupVaultEventHandlersDesktop();
    } else {
      this.setupVaultEventHandlersMobile();
    }
  }

  /**
   * Mobile: контент уже шифруется в .enc через AdapterPatcher (write-through
   * на adapter.write/remove/rename). Vault-события здесь информативны —
   * мы лишь логируем их; повторное шифрование не требуется и привело бы
   * к двойной работе. Папки на mobile хранятся plaintext (не шифруются),
   * их создание/удаление идёт через нетронутый adapter.mkdir/rmdir.
   */
  private setupVaultEventHandlersMobile(): void {
    const configDir = this.app.vault.configDir;
    const isConfigPath = (p: string) => p === configDir || p.startsWith(configDir + "/");

    const log = (kind: string, path: string) => {
      if (isConfigPath(path)) return;
      console.debug(`[ShadowVault:event:mobile] ${kind} ${path} (write-through via AdapterPatcher)`);
    };

    this.registerEvent(this.app.vault.on("create", (file) => log("create", file.path)));
    this.registerEvent(this.app.vault.on("modify", (file) => log("modify", file.path)));
    this.registerEvent(this.app.vault.on("delete", (file) => log("delete", file.path)));
    this.registerEvent(this.app.vault.on("rename", (file, oldPath) => log("rename", `${oldPath} → ${file.path}`)));

    console.info("[ShadowVault] mobile vault event handlers подписаны (логирование, write-through на AdapterPatcher)");
  }

  /**
   * Desktop: Obsidian работает в shadow натив но, мы зеркалим изменения
   * в оригинал.enc через стандартный API.
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
  /**
   * Гейт жизненного цикла для vault-обработчиков. Возвращает живой
   * ShadowManager ТОЛЬКО если сессия активна, shutdown не начат и менеджер
   * не обнулён. Иначе null — обработчик обязан безопасно выйти (ранний return),
   * не дереференсить менеджер и не бросать исключение.
   *
   * Устраняет гонку: события Obsidian (autosave/flush) могут прилетать ПОСЛЕ
   * того как shutdown() обнулил shadowManager → раньше это давало
   * `TypeError: Cannot read properties of null (reading 'trackPending')`.
   */
  private liveShadowManager(reason: string): ShadowVaultManager | null {
    if (this.shuttingDown || !this.sessionActive || !this.shadowManager) {
      this.logger?.debug(
        "write",
        "vault-событие проигнорировано: менеджер не инициализирован / идёт завершение",
        { reason, shuttingDown: this.shuttingDown, sessionActive: this.sessionActive },
      );
      return null;
    }
    return this.shadowManager;
  }

  private setupVaultEventHandlersDesktop(): void {
    const configDir = this.app.vault.configDir;
    const isConfigPath = (p: string) => p === configDir || p.startsWith(configDir + "/");

    this.registerEvent(this.app.vault.on("create", (file) => {
      try {
        if (isConfigPath(file.path)) return;
        const sm = this.liveShadowManager(`create ${file.path}`);
        if (!sm) return;
        console.debug(`[ShadowVault:event] create ${file.path}`);
        // Регистрируем в pendingWrites — onunload дренирует их перед удалением shadow.
        void sm.trackPending(this.handleCreate(file));
      } catch (err) {
        // Обработчик вызывается fire-and-forget — исключение всплыло бы в
        // window.error и породило лавину баг-репортов. Глушим тут.
        console.error(`[ShadowVault:event] create handler ${file.path}:`, err);
        void this.reportError("write.create.handler", err, { path: file.path }, { silent: true });
      }
    }));

    this.registerEvent(this.app.vault.on("modify", (file) => {
      try {
        if (isConfigPath(file.path)) return;
        if (!(file instanceof TFile)) return;
        const sm = this.liveShadowManager(`modify ${file.path}`);
        if (!sm) return;
        console.debug(`[ShadowVault:event] modify ${file.path}`);
        // КРИТИЧНО: promise регистрируется в pendingWrites, иначе последняя правка
        // могла потеряться, если onunload удалит shadow до завершения encryptOne.
        const t0 = Date.now();
        void sm.trackPending(
          sm.encryptOne(file.path)
            .then(() => this.logger.debug("write", "modify→encrypt", { path: file.path, ms: Date.now() - t0 }))
            .catch((err) => {
              console.error(`[ShadowVault:event] modify ${file.path} failed:`, err);
              void this.reportError("write.modify", err, { path: file.path }, { silent: true });
            })
        );
      } catch (err) {
        console.error(`[ShadowVault:event] modify handler ${file.path}:`, err);
        void this.reportError("write.modify.handler", err, { path: file.path }, { silent: true });
      }
    }));

    this.registerEvent(this.app.vault.on("delete", (file) => {
      try {
        if (isConfigPath(file.path)) return;
        const sm = this.liveShadowManager(`delete ${file.path}`);
        if (!sm) return;
        console.debug(`[ShadowVault:event] delete ${file.path}`);
        void sm.trackPending(this.handleDelete(file));
      } catch (err) {
        console.error(`[ShadowVault:event] delete handler ${file.path}:`, err);
        void this.reportError("write.delete.handler", err, { path: file.path }, { silent: true });
      }
    }));

    this.registerEvent(this.app.vault.on("rename", (file, oldPath) => {
      try {
        if (isConfigPath(file.path) || isConfigPath(oldPath)) return;
        const sm = this.liveShadowManager(`rename ${oldPath} → ${file.path}`);
        if (!sm) return;
        console.debug(`[ShadowVault:event] rename ${oldPath} → ${file.path}`);
        void sm.trackPending(this.handleRename(file, oldPath));
      } catch (err) {
        console.error(`[ShadowVault:event] rename handler ${oldPath} → ${file.path}:`, err);
        void this.reportError("write.rename.handler", err, { from: oldPath, to: file.path }, { silent: true });
      }
    }));

    console.info("[ShadowVault] vault event handlers подписаны");
  }

  private async handleCreate(file: TAbstractFile): Promise<void> {
    try {
      const sm = this.liveShadowManager(`handleCreate ${file.path}`);
      if (!sm) return;
      if (file instanceof TFile) {
        await sm.encryptOne(file.path);
      } else if (file instanceof TFolder) {
        await sm.mkdirOriginal(file.path);
      }
      this.logger.debug("write", "create→encrypt", { path: file.path });
    } catch (err) {
      console.error(`[ShadowVault:event] create ${file.path}:`, err);
      void this.reportError("write.create", err, { path: file.path }, { silent: true });
    }
  }

  private async handleDelete(file: TAbstractFile): Promise<void> {
    try {
      const sm = this.liveShadowManager(`handleDelete ${file.path}`);
      if (!sm) return;
      if (file instanceof TFile) {
        await sm.unlinkEnc(file.path);
      } else if (file instanceof TFolder) {
        await sm.rmdirOriginal(file.path);
      }
      this.logger.debug("write", "delete→unlink", { path: file.path });
    } catch (err) {
      console.error(`[ShadowVault:event] delete ${file.path}:`, err);
      void this.reportError("write.delete", err, { path: file.path }, { silent: true });
    }
  }

  private async handleRename(file: TAbstractFile, oldPath: string): Promise<void> {
    try {
      const sm = this.liveShadowManager(`handleRename ${oldPath} → ${file.path}`);
      if (!sm) return;
      if (file instanceof TFile) {
        await sm.renameEnc(oldPath, file.path);
      } else if (file instanceof TFolder) {
        // Папка: переименовать в оригинале (там тоже структура с .enc).
        // КРИТИЧНО: сначала дренируем in-flight write-through, иначе
        // fsp.rename каталога мог унести .enc «из-под» ещё пишущегося encryptOne
        // (несогласованное состояние). drainPending гарантирует, что все
        // незавершённые шифрования под старым путём завершены.
        await sm.drainPending();
        const nodePath = npath();
        const fsp = nfsp();
        const oldOrig = nodePath.join(sm.originalRoot, ...oldPath.split("/"));
        const newOrig = nodePath.join(sm.originalRoot, ...file.path.split("/"));
        await fsp.mkdir(nodePath.dirname(newOrig), { recursive: true });
        await fsp.rename(oldOrig, newOrig);
      }
      this.logger.debug("write", "rename", { from: oldPath, to: file.path });
    } catch (err) {
      console.error(`[ShadowVault:event] rename ${oldPath} → ${file.path}:`, err);
      void this.reportError("write.rename", err, { from: oldPath, to: file.path }, { silent: true });
    }
  }

  /**
   * Абсолютный путь к папке плагина: <vault>/.obsidian/plugins/<id>.
   * Используем для хранения session.lock — чтобы не засорять оригинальное
   * хранилище и не попадать под Obsidian-индексацию.
   */
  private getPluginDirAbs(originalRoot: string): string {
    return npath().join(
      originalRoot,
      this.app.vault.configDir,
      "plugins",
      this.manifest.id
    );
  }

  // setupQueue() удалён: bulk decrypt в setupShadow покрывает весь vault единоразово.

  /**
   * Освобождает частично созданное состояние при ошибке инициализации.
   *
   * sessionActive здесь остаётся false, поэтому onunload/syncCleanup НЕ
   * подчистят теневой каталог и session.lock — делаем это ЯВНО тут, иначе
   * после ошибки init на диске остаётся осиротевший .shadow-vault-<hash> и
   * session.lock (при следующем входе ложно сработает crash-recovery).
   *
   * Безопасность: на этапе init в shadow ещё НЕТ несохранённых пользовательских
   * правок (mount/события не подключены или сессия не стартовала), поэтому
   * удаление пустого/только-что-расшифрованного shadow данные не теряет.
   * Чужой непустой shadow с реальными изменениями не трогаем.
   */
  private async rollbackInitialization(
    engine: CryptoEngine | WebCryptoEngine
  ): Promise<void> {
    engine.destroy();

    // Захватываем путь shadow ДО обнуления менеджера (desktop).
    const shadowRoot = this.isDesktop ? this.shadowManager?.shadowRoot ?? null : null;

    if (this.shadowManager) {
      const adapter = this.app.vault.adapter as unknown as IDataAdapter;
      this.shadowManager.unpatch(adapter);
      this.shadowManager.unmount(adapter);
      this.shadowManager = null;
    }
    this.sessionManager = null;

    // Desktop: удаляем осиротевший shadow + session.lock (лениво через node-fs).
    if (this.isDesktop) {
      try {
        await this.cleanupOrphanShadow(shadowRoot);
      } catch (err) {
        console.error("[ShadowVault] rollback cleanup:", err);
      }
    }
  }

  /**
   * Удаляет свежесозданный теневой каталог и session.lock после неудачной
   * инициализации (desktop-only, node лениво). Не вызывается на mobile.
   */
  private async cleanupOrphanShadow(shadowRoot: string | null): Promise<void> {
    const fs = nfs();
    // session.lock в папке плагина — удаляем безусловно (его пишет startSession).
    const basePath = this.getVaultBasePath();
    if (basePath) {
      const lock = npath().join(this.getPluginDirAbs(basePath), "session.lock");
      try { fs.rmSync(lock, { force: true }); } catch { /* нет — ок */ }
    }
    if (!shadowRoot) return;
    try {
      fs.rmSync(shadowRoot, { recursive: true, force: true });
      console.info("[ShadowVault] rollback: удалён осиротевший shadow:", shadowRoot);
    } catch (err) {
      console.error("[ShadowVault] rollback: не удалось удалить shadow:", err);
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
   *   1. encryptShadowChangesToOriginal() — финальная синхронизация изменений
   *      из shadow в оригинал.enc (страховка от пропущенных write-through).
   *   2. unpatch() и unmount() — восстанавливаем адаптер до оригинала,
   *      ПЕРЕД удалением shadow vault, чтобы Obsidian не обращался к нему.
   *   3. teardownObsidianSymlink() — снимаем symlink .obsidian.
   *   4. SessionManager.endSession() — удаляем shadow vault, уничтожаем ключ.
   */
  async shutdown(): Promise<void> {
    if (!this.sessionActive) return;
    // Взводим гейт ДО любых действий: новые vault-события (autosave/flush) с
    // этого момента игнорируются обработчиками (liveShadowManager вернёт null),
    // чтобы они не дереференсили вот-вот обнуляемый shadowManager. При этом все
    // ранее зарегистрированные правки уже в pendingWrites и будут дренированы
    // ниже — дошифровка последней правки не теряется.
    this.shuttingDown = true;
    this.sessionActive = false;

    this.logger.info("shutdown", "завершение сессии: старт");
    console.debug("[ShadowVault] Завершение сессии...");

    // 0. Дренаж in-flight write-through: дожидаемся завершения всех
    //    незавершённых encryptOne (modify-обработчики работают через void),
    //    иначе финальный encrypt-back/удаление shadow могли бы обогнать
    //    ещё пишущуюся последнюю правку.
    if (this.shadowManager) {
      try {
        await this.shadowManager.drainPending();
      } catch (err) {
        console.error("[ShadowVault] shutdown drainPending:", err);
      }
    }

    // 1. Финальный encrypt-back: страховка на случай если write-through
    //    что-то пропустил (например, файл был изменён сторонним процессом в shadow)
    if (this.shadowManager) {
      try {
        const r = await this.shadowManager.encryptShadowChangesToOriginal();
        this.logger.info("shutdown", "финальный encrypt-back", {
          encrypted: r.encrypted.length,
          failed: r.failed.length,
        });
        if (r.encrypted.length > 0) {
          console.debug(`[ShadowVault] shutdown encrypt-back: ${r.encrypted.length} файлов синхронизировано`);
        }
        if (r.failed.length > 0) {
          this.logger.warn("shutdown", "shadow сохранён для recovery (есть незашифрованные)", {
            failed: r.failed.length,
          });
          console.error("[ShadowVault] shutdown encrypt-back: failed:", r.failed);
          new Notice(
            `⚠️ Shadow Vault: не удалось зашифровать ${r.failed.length} файл(ов) при выходе. ` +
            `Shadow vault сохранён для recovery при следующем запуске.`,
            10000
          );
        }
      } catch (err) {
        console.error("[ShadowVault] shutdown encrypt-back ошибка:", err);
        await this.reportError("shutdown.encryptBack", err);
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

    // Сбрасываем гейт: сессия полностью завершена, менеджер обнулён. Следующий
    // unlock (например после lockVault) стартует с чистого состояния.
    this.shuttingDown = false;

    this.logger.info("shutdown", "сессия завершена");
    console.debug("[ShadowVault] Сессия завершена.");
  }

  /**
   * Синхронная очистка мобильной сессии (вызывается из beforeunload)
   */
  private syncCleanupMobile(): void {
    console.info("[ShadowVault] syncCleanupMobile: старт");

    this.shuttingDown = true;
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
        ? npath().join(originalRoot, ...normalizedPath.split("/"))
        : originalRoot;

      // Единый list-транслятор .enc → имена (см. fs-utils.listEncryptedDir).
      return listEncryptedDir(absDir, normalizedPath, configDir);
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

      let statObj: { ctime: number; mtime: number; size: number };

      if (this.isDesktop) {
        // Desktop: защита от каскадных ENOENT — регистрируем файл только если он
        // ФАКТИЧЕСКИ существует в shadow (т.е. был успешно расшифрован).
        // Файлы из decryptAllToShadow.failed[] есть в .enc, но не в shadow —
        // если их зарегистрировать, любой клик пользователя приведёт к
        // ENOENT при native readFile/lstat.
        // notifyFilesCreated вызывается в awaited-фазе unlock, где менеджер уже
        // создан; но на всякий случай проверяем, чтобы не дереференсить null.
        if (!this.shadowManager) break;
        const shadowAbs = this.shadowManager.shadowAbs(filePath);
        const fsp = nfsp();
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
        statObj = s
          ? {
              ctime: Math.round(s.birthtimeMs ?? s.ctimeMs),
              mtime: Math.round(s.mtimeMs),
              size: s.size,
            }
          : { ctime: Date.now(), mtime: Date.now(), size: 0 };
      } else {
        // Mobile: shadow виртуальный (in-memory). Метаданные берём через
        // пропатченный adapter.stat → VirtualShadowManager (читает .enc-stat).
        const s = await this.app.vault.adapter.stat(filePath).catch(() => null);
        statObj = s
          ? { ctime: s.ctime ?? s.mtime, mtime: s.mtime, size: s.size }
          : { ctime: Date.now(), mtime: Date.now(), size: 0 };
      }

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
    this.shuttingDown = true;
    this.sessionActive = false;

    const adapter = this.app.vault.adapter as unknown as IDataAdapter;
    const fs = nfs();
    const nodePath = npath();
    console.info("[ShadowVault] syncCleanup: старт");

    if (this.shadowManager) {
      const shadowRoot = this.shadowManager.shadowRoot;
      const originalRoot = this.shadowManager.originalRoot;

      // 0. ФИНАЛЬНАЯ ДОШИФРОВКА несхороненных правок (закрывает окно потери
      //    последней правки: modify-обработчик мог не успеть завершить encryptOne
      //    до закрытия Obsidian). Делаем синхронно — onunload не ждёт async.
      let unsyncedRemain = false;
      try {
        const r = this.shadowManager.encryptUnsyncedChangesSync();
        if (r.encrypted > 0) {
          console.info(`[ShadowVault] sync encrypt-back: дошифровано ${r.encrypted} файл(ов) при закрытии`);
        }
        if (r.failed.length > 0) {
          unsyncedRemain = true;
          console.error(`[ShadowVault] sync encrypt-back: не удалось ${r.failed.length} файл(ов):`, r.failed);
        }
      } catch (e) {
        unsyncedRemain = true;
        console.error("[ShadowVault] sync encrypt-back ошибка:", e);
      }
      // Повторная сверка: остались ли несхороненные изменения после дошифровки.
      try {
        if (this.shadowManager.hasUnsyncedChangesSync()) unsyncedRemain = true;
      } catch (e) {
        unsyncedRemain = true;
        console.error("[ShadowVault] sync проверка несхороненных:", e);
      }

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

      // 3. shadow vault recursive — ТОЛЬКО если всё гарантированно дошифровано.
      //    Если остались несхороненные изменения — НЕ удаляем shadow: лучше
      //    оставить его для crash recovery при следующем старте, чем потерять данные.
      if (unsyncedRemain) {
        console.warn(
          `[ShadowVault] sync: обнаружены несхороненные изменения — shadow НЕ удаляем ` +
          `(${shadowRoot}). Данные восстановятся через recovery при следующем запуске.`
        );
      } else {
        try {
          fs.rmSync(shadowRoot, { recursive: true, force: true });
          console.info(`[ShadowVault] sync rm shadow ok: ${shadowRoot}`);
        } catch (e) {
          console.error(`[ShadowVault] sync rm shadow ${shadowRoot}:`, e);
        }
      }

      // 4. session.lock — снимаем только если shadow удалён (чистый выход).
      //    Если shadow оставлен для recovery, lock тоже оставляем, чтобы
      //    следующий старт распознал незавершённую сессию.
      if (!unsyncedRemain) {
        const lockPath = nodePath.join(this.getPluginDirAbs(originalRoot), "session.lock");
        try {
          fs.unlinkSync(lockPath);
          console.debug(`[ShadowVault] sync unlink lock: ${lockPath}`);
        } catch (e) {
          const code = (e as NodeJS.ErrnoException).code;
          if (code !== "ENOENT") console.error("[ShadowVault] sync unlink lock:", e);
        }
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
