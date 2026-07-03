/**
 * ShadowVaultSettingTab — вкладка настроек плагина в Obsidian Settings.
 *
 * Предоставляет:
 *   - Кнопку "Заблокировать хранилище" (ручная блокировка)
 *   - Смену учётных данных (email/пароль) с пере-шифровкой
 *   - Зону опасных действий: расшифровать хранилище / сброс конфигурации
 */

import { App, Notice, Platform, PluginSettingTab, Setting } from "obsidian";
import type ShadowVaultPlugin from "./main";
import { ChangeCredentialsModal } from "./change-password-modal";
import { ConfirmModal } from "./confirm-modal";
import { SetPinModal } from "./set-pin-modal";
import { PinStore } from "./pin-store";
import { LogLevel } from "./logger";

export class ShadowVaultSettingTab extends PluginSettingTab {
  constructor(app: App, private readonly plugin: ShadowVaultPlugin) {
    super(app, plugin);
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    new Setting(containerEl).setName("Shadow Vault").setHeading();

    const isDormant = this.plugin.settings.encryptionDisabled;

    if (isDormant) {
      // ── Спящий режим: только переключатель «Зашифровать заново» ─────
      new Setting(containerEl)
        .setName("Состояние")
        .setDesc(
          "Шифрование отключено. Файлы хранятся в открытом виде. " +
          "Чтобы снова защитить хранилище паролем — нажмите кнопку ниже " +
          "и перезапустите Obsidian."
        );

      new Setting(containerEl)
        .setName("Зашифровать хранилище")
        .setDesc(
          "Включить шифрование заново. После перезапуска Obsidian плагин " +
          "запросит пароль и зашифрует все файлы хранилища."
        )
        .addButton((btn) => {
          btn
            .setButtonText("Зашифровать")
            .setCta()
            .onClick(() => {
              new ConfirmModal(
                this.app,
                "После перезапуска Obsidian плагин запросит новый пароль и зашифрует все файлы. Продолжить?",
                (confirmed) => {
                  if (!confirmed) return;
                  void this.plugin.enableEncryption().then(() => {
                    new Notice(
                      "🔐 Шифрование включено. Перезапустите Obsidian для применения.",
                      8000
                    );
                  });
                }
              ).open();
            });
        });
      return;
    }

    // ── Статус сессии ──────────────────────────────────────────────────
    new Setting(containerEl)
      .setName("Заблокировать хранилище")
      .setDesc("Немедленно завершить сессию: удалить теневое хранилище и потребовать пароль снова.")
      .addButton((btn) => {
        btn
          .setButtonText("🔒 Заблокировать")
          .setWarning()
          .onClick(async () => {
            // Guard как у соседних кнопок: без него повторный клик при уже
            // запертом хранилище открывал ВТОРОЙ InitModal поверх первого.
            if (!this.plugin.isUnlocked()) {
              new Notice("🔒 Хранилище уже заблокировано.", 4000);
              return;
            }
            await this.plugin.lockVault();
          });
      });

    // ── Учётная запись (email) ─────────────────────────────────────────
    new Setting(containerEl).setName("Учётная запись").setHeading();

    new Setting(containerEl)
      .setName("Email / пароль")
      .setDesc(
        `Текущий email: ${this.plugin.settings.email || "(не задан)"}. ` +
        "Email задаёт соль деривации ключа. Можно сменить email и/или пароль за " +
        "одну пере-шифровку. Требует разблокированного хранилища; создайте " +
        "резервную копию заранее."
      )
      .addButton((btn) => {
        btn
          .setButtonText("Сменить email/пароль")
          .onClick(() => {
            if (!this.plugin.isUnlocked()) {
              new Notice("🔒 Сначала разблокируйте хранилище.", 4000);
              return;
            }
            new ChangeCredentialsModal(this.app, this.plugin).open();
          });
      });

    // ── Быстрый вход: PIN ──────────────────────────────────────────────
    new Setting(containerEl).setName("Быстрый вход").setHeading();

    const pinStore = new PinStore();
    const pinSet = pinStore.isPinSet();

    new Setting(containerEl)
      .setName("PIN-код")
      .setDesc(
        pinSet
          ? "PIN настроен для этого устройства (хранится локально, не синхронизируется)."
          : "Задайте PIN (4–8 цифр) для быстрого входа на этом устройстве. " +
            "PIN не заменяет пароль и хранится только локально."
      )
      .addButton((btn) => {
        btn
          .setButtonText(pinSet ? "Сменить PIN" : "Задать PIN")
          .onClick(() => {
            if (this.plugin.settings.verificationBlob === null) {
              new Notice("🔒 Сначала создайте/разблокируйте хранилище.", 4000);
              return;
            }
            new SetPinModal(this.app, this.plugin).open();
          });
      });

    if (pinSet) {
      new Setting(containerEl)
        .setName("Удалить PIN")
        .setDesc("Отключить быстрый вход по PIN на этом устройстве.")
        .addButton((btn) => {
          btn
            .setButtonText("Удалить PIN")
            .setWarning()
            .onClick(() => {
              this.plugin.removePin();
              new Notice("PIN удалён с этого устройства.", 4000);
              this.display();
            });
        });
    }

    // ── Биометрия (опционально, точка расширения) ──────────────────────
    const biometricSupported = pinStore.isBiometricSupported();
    new Setting(containerEl)
      .setName("Биометрия")
      .setDesc(
        biometricSupported
          ? "Разблокировка по биометрии (тот же локальный механизм, что и PIN)."
          : "Биометрия пока недоступна: плагин Obsidian в песочнице не имеет " +
            "прямого доступа к FaceID/Touch ID. Будет включена, когда появится " +
            "поддерживаемый API устройства."
      )
      .addToggle((tg) => {
        tg
          .setValue(pinStore.isBiometricEnabled())
          .setDisabled(!biometricSupported) // TODO(биометрия): нет нативного API
          .onChange((v) => {
            pinStore.setBiometricEnabled(v);
          });
      });

    // ── Диагностика / Логи ─────────────────────────────────────────────
    this.renderDiagnostics(containerEl);

    // ── Опасная зона ───────────────────────────────────────────────────
    new Setting(containerEl).setName("Опасная зона").setHeading();

    new Setting(containerEl)
      .setName("Расшифровать хранилище")
      .setDesc(
        "Превратить все .enc файлы обратно в открытые и отключить шифрование. " +
        "Пароль будет удалён, плагин перейдёт в спящий режим: Obsidian " +
        "будет работать с файлами напрямую без шифрования. " +
        "Требует разблокированного хранилища."
      )
      .addButton((btn) => {
        btn
          .setButtonText("Расшифровать")
          .setWarning()
          .onClick(() => {
            if (!this.plugin.isUnlocked()) {
              new Notice("🔒 Сначала разблокируйте хранилище.", 4000);
              return;
            }
            new ConfirmModal(
              this.app,
              "Все файлы станут открытым текстом, пароль будет удалён. Шифрование отключится. Продолжить?",
              (confirmed) => {
                if (!confirmed) return;
                const progress = new Notice("⏳ Расшифровка хранилища...", 0);
                void this.plugin
                  .disableEncryption((done, total, current) => {
                    const percent = total > 0 ? Math.round((done / total) * 100) : 0;
                    progress.setMessage(
                      `⏳ Расшифровка: ${done}/${total} (${percent}%)\n${current.slice(-60)}`
                    );
                  })
                  .then(() => {
                    progress.hide();
                    new Notice(
                      "✅ Шифрование отключено. Перезапустите Obsidian для применения.",
                      8000
                    );
                  })
                  .catch((err) => {
                    progress.hide();
                    console.error("[ShadowVault] disableEncryption failed:", err);
                    new Notice(`❌ Ошибка: ${err instanceof Error ? err.message : String(err)}`, 10000);
                  });
              }
            ).open();
          });
      });
  }

  /**
   * Секция «Диагностика / Логи»: уровень логирования, работа с папкой логов
   * и баг-репортами. Кросс-платформенно: на desktop пытаемся открыть папку
   * в файловом менеджере, на mobile показываем путь.
   */
  private renderDiagnostics(containerEl: HTMLElement): void {
    const plugin = this.plugin;
    if (!plugin.logger) return;

    new Setting(containerEl).setName("Диагностика / Логи").setHeading();

    // Тумблер подробного логирования (DEBUG).
    new Setting(containerEl)
      .setName("Подробное логирование (debug)")
      .setDesc(
        "Включает детальные debug-логи всех операций. Логи и баг-репорты " +
        "сохраняются локально в папке плагина. Секреты (пароль/PIN/ключи/" +
        "содержимое файлов) НЕ логируются."
      )
      .addToggle((tg) => {
        tg
          .setValue(plugin.logger.getMinLevel() <= LogLevel.DEBUG)
          .onChange((v) => {
            plugin.logger.setMinLevel(v ? LogLevel.DEBUG : LogLevel.INFO);
            new Notice(v ? "Подробное логирование включено." : "Логирование: только важные события.", 3000);
          });
      });

    // Открыть папку логов.
    new Setting(containerEl)
      .setName("Папка логов и баг-репортов")
      .setDesc(plugin.logger.logDir)
      .addButton((btn) => {
        btn.setButtonText("Открыть папку").onClick(() => {
          void this.openLogFolder();
        });
      });

    // Показать последние баг-репорты.
    new Setting(containerEl)
      .setName("Баг-репорты")
      .setDesc("Показать список сохранённых баг-репортов (создаются автоматически при ошибках).")
      .addButton((btn) => {
        btn.setButtonText("Показать последние").onClick(() => {
          void this.showBugReports();
        });
      });

    // Очистить логи и репорты.
    new Setting(containerEl)
      .setName("Очистить логи и баг-репорты")
      .setDesc("Удалить все файлы логов и сохранённые баг-репорты с устройства.")
      .addButton((btn) => {
        btn
          .setButtonText("Очистить")
          .setWarning()
          .onClick(() => {
            new ConfirmModal(
              this.app,
              "Удалить все логи и баг-репорты? Действие необратимо.",
              (confirmed) => {
                if (!confirmed) return;
                void Promise.all([plugin.logger.clear(), plugin.bugReporter.clear()]).then(() => {
                  new Notice("Логи и баг-репорты очищены.", 4000);
                });
              }
            ).open();
          });
      });
  }

  /** Открывает папку логов: desktop — в файловом менеджере, mobile — Notice. */
  private async openLogFolder(): Promise<void> {
    const dir = this.plugin.logger.logDir;
    if (Platform.isDesktopApp) {
      try {
        // Ленивый доступ к node:path только в desktop-ветке.
        const { npath } = await import("./node-fs");
        const basePath = (this.app.vault.adapter as unknown as { getBasePath?: () => string }).getBasePath?.();
        const abs = basePath ? npath().join(basePath, dir) : dir;
        const electron = (globalThis as unknown as { require?: (m: string) => unknown }).require?.("electron") as
          | { shell?: { openPath: (p: string) => Promise<string> } }
          | undefined;
        if (electron?.shell) {
          await electron.shell.openPath(abs);
          return;
        }
        new Notice(`Папка логов:\n${abs}`, 8000);
      } catch {
        new Notice(`Папка логов:\n${dir}`, 8000);
      }
    } else {
      new Notice(`Папка логов (внутри хранилища):\n${dir}`, 8000);
    }
  }

  /** Показывает список последних баг-репортов через Notice. */
  private async showBugReports(): Promise<void> {
    const reports = await this.plugin.bugReporter.list();
    if (reports.length === 0) {
      new Notice("Баг-репортов нет.", 4000);
      return;
    }
    const head = reports.slice(0, 10).map((p) => "• " + p.split("/").pop()).join("\n");
    new Notice(`Последние баг-репорты (${reports.length}):\n${head}`, 12000);
  }
}
