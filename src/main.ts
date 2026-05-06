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

import { App, Notice, Plugin, TFile } from "obsidian";
import { CryptoEngine } from "./crypto-engine";
import { AuthResult } from "./auth-service";
import { InitModal } from "./init-modal";
import { ShadowVaultManager } from "./shadow-vault-manager";
import { SessionManager } from "./session-manager";
import { QueueManager } from "./queue-manager";
import { QueueIntegration } from "./queue-integration";
import { ShadowVaultSettingTab } from "./settings-tab";
import { DEFAULT_SETTINGS, PluginSettings } from "./types";
import { IDataAdapter } from "./adapter-types";

export default class ShadowVaultPlugin extends Plugin {
  /** Настройки плагина — читаются из data.json, записываются через saveSettings() */
  settings: PluginSettings = { ...DEFAULT_SETTINGS };

  // Модули, создаются только после успешной аутентификации
  private shadowManager:    ShadowVaultManager | null = null;
  private sessionManager:   SessionManager     | null = null;
  private queueIntegration: QueueIntegration   | null = null;

  /** true только пока сессия активна (между onUnlock и shutdown) */
  private sessionActive = false;

  // ═══════════════════════════════════════════════════════════════════════
  // Жизненный цикл плагина
  // ═══════════════════════════════════════════════════════════════════════

  async onload(): Promise<void> {
    await this.loadSettings();

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

      // Патчим адаптер ДО startSession — чтобы операции recovery шли
      // через правильные пути (bypass для .obsidian и т.д.)
      this.shadowManager.patch(
        this.app.vault.adapter as unknown as IDataAdapter
      );

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
}
