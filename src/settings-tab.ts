/**
 * ShadowVaultSettingTab — вкладка настроек плагина в Obsidian Settings.
 *
 * Предоставляет:
 *   - Поле для кастомного пути к Теневому хранилищу
 *   - Кнопку "Заблокировать хранилище" (ручная блокировка)
 *   - Зону опасных действий: смена пароля, сброс конфигурации
 */

import { App, Notice, PluginSettingTab, Setting } from "obsidian";
import type ShadowVaultPlugin from "./main";
import { ChangePasswordModal } from "./change-password-modal";
import { ConfirmModal } from "./confirm-modal";

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

    // ── Путь к теневому хранилищу ──────────────────────────────────────
    new Setting(containerEl)
      .setName("Путь к теневому хранилищу")
      .setDesc(
        "Директория для временных расшифрованных файлов. " +
        "Оставьте пустым для автоматического выбора во временной папке ОС. " +
        "Изменение вступит в силу при следующем запуске."
      )
      .addText((text) => {
        text
          .setPlaceholder("По умолчанию: /tmp/shadowvault-…")
          .setValue(this.plugin.settings.shadowVaultPath)
          .onChange(async (value) => {
            this.plugin.settings.shadowVaultPath = value.trim();
            await this.plugin.saveSettings();
          });
      });

    // ── Статус сессии ──────────────────────────────────────────────────
    new Setting(containerEl)
      .setName("Заблокировать хранилище")
      .setDesc("Немедленно завершить сессию: удалить теневое хранилище и потребовать пароль снова.")
      .addButton((btn) => {
        btn
          .setButtonText("🔒 Заблокировать")
          .setWarning()
          .onClick(async () => {
            await this.plugin.lockVault();
          });
      });

    // ── Опасная зона ───────────────────────────────────────────────────
    new Setting(containerEl).setName("Опасная зона").setHeading();

    new Setting(containerEl)
      .setName("Сменить пароль")
      .setDesc(
        "Пере-шифровать все файлы с новым паролем. " +
        "Требует разблокированного хранилища. Создайте резервную копию заранее."
      )
      .addButton((btn) => {
        btn
          .setButtonText("Сменить пароль")
          .onClick(() => {
            if (!this.plugin.isUnlocked()) {
              new Notice("🔒 Сначала разблокируйте хранилище.", 4000);
              return;
            }
            new ChangePasswordModal(this.app, this.plugin).open();
          });
      });

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
}
