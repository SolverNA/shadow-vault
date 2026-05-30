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
import { SetPinModal } from "./set-pin-modal";
import { PinStore } from "./pin-store";

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

    // ── Учётная запись (email) ─────────────────────────────────────────
    new Setting(containerEl).setName("Учётная запись").setHeading();

    new Setting(containerEl)
      .setName("Email")
      .setDesc(
        "Email задаёт соль деривации ключа. Сейчас смену email делать НЕЛЬЗЯ: " +
        "новый email = новый ключ = существующие файлы станут нечитаемыми " +
        "без перешифровки (запланировано на будущей фазе миграции)."
      )
      .addText((text) => {
        text
          .setValue(this.plugin.settings.email || "(не задан)")
          .setDisabled(true); // read-only: смена email = TODO(ФАЗА 4 миграция)
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
