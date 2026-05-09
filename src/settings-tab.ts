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
      .setName("Сбросить конфигурацию шифрования")
      .setDesc(
        "Удалить верификационный блоб из настроек. " +
        "При следующем запуске потребуется создать новое хранилище. " +
        "Зашифрованные файлы СТАНУТ НЕДОСТУПНЫ без старого пароля."
      )
      .addButton((btn) => {
        btn
          .setButtonText("Сбросить")
          .setWarning()
          .onClick(() => {
            new ConfirmModal(
              this.app,
              "Вы уверены? Это действие необратимо.",
              (confirmed) => {
                if (!confirmed) return;
                this.plugin.settings.verificationBlob = null;
                void this.plugin.saveSettings().then(() => {
                  new Notice("🔑 Конфигурация сброшена. Перезапустите Obsidian.", 5000);
                });
              }
            ).open();
          });
      });
  }
}
