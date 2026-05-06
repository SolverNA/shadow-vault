/**
 * ShadowVaultSettingTab — вкладка настроек плагина в Obsidian Settings.
 *
 * Предоставляет:
 *   - Поле для кастомного пути к Теневому хранилищу
 *   - Кнопку "Заблокировать хранилище" (ручная блокировка)
 *   - Зону опасных действий: смена пароля
 */

import { App, Notice, PluginSettingTab, Setting } from "obsidian";
import type ShadowVaultPlugin from "./main";

export class ShadowVaultSettingTab extends PluginSettingTab {
  constructor(app: App, private readonly plugin: ShadowVaultPlugin) {
    super(app, plugin);
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl("h2", { text: "ShadowVault — Настройки" });

    // ── Путь к теневому хранилищу ──────────────────────────────────────
    new Setting(containerEl)
      .setName("Путь к Теневому хранилищу")
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
    containerEl.createEl("h3", { text: "⚠️ Опасная зона" });

    new Setting(containerEl)
      .setName("Сменить пароль")
      .setDesc(
        "Расшифровать все файлы и зашифровать их заново с новым паролем. " +
        "Операция необратима. Создайте резервную копию перед сменой."
      )
      .addButton((btn) => {
        btn
          .setButtonText("Сменить пароль")
          .onClick(() => {
            new Notice("⚠️ Смена пароля будет доступна в следующей версии.", 4000);
          });
      });

    new Setting(containerEl)
      .setName("Сбросить конфигурацию шифрования")
      .setDesc(
        "Удалить соль и верификационный блоб из настроек. " +
        "При следующем запуске потребуется создать новое хранилище. " +
        "Зашифрованные файлы СТАНУТ НЕДОСТУПНЫ без старого пароля."
      )
      .addButton((btn) => {
        btn
          .setButtonText("Сбросить")
          .setWarning()
          .onClick(async () => {
            if (confirm("Вы уверены? Это действие необратимо.")) {
              this.plugin.settings.saltHex = null;
              this.plugin.settings.verificationBlob = null;
              await this.plugin.saveSettings();
              new Notice("🔑 Конфигурация сброшена. Перезапустите Obsidian.", 5000);
            }
          });
      });
  }
}
