/**
 * SetPinModal — задание/смена PIN для быстрого локального входа.
 *
 * Требует подтверждения текущим паролем (из него re-деривируется masterKey,
 * который оборачивается ключом из PIN — см. PinStore). PIN-данные сохраняются
 * device-local (localStorage), НЕ в data.json.
 */

import { App, Modal, Notice } from "obsidian";
import { PasswordError } from "./auth-service";
import { createPasswordField } from "./password-field";
import type ShadowVaultPlugin from "./main";

export class SetPinModal extends Modal {
  private inputPwd!: HTMLInputElement;
  private inputPin!: HTMLInputElement;
  private inputPinConfirm!: HTMLInputElement;
  private btnSubmit!: HTMLButtonElement;
  private errorEl!: HTMLElement;

  /** true — setupPin в процессе: повторный сабмит (Enter/кнопка) игнорируется */
  private busy = false;

  constructor(app: App, private readonly plugin: ShadowVaultPlugin) {
    super(app);
  }

  onOpen(): void {
    const { contentEl, modalEl } = this;
    modalEl.addClass("shadow-vault-modal");
    contentEl.empty();

    contentEl.createEl("div", { cls: "shadow-vault-header" }, (h) => {
      h.createEl("div", { cls: "shadow-vault-icon", text: "🔢" });
      h.createEl("h2", { cls: "shadow-vault-title", text: "PIN-код для быстрого входа" });
      h.createEl("p", {
        cls: "shadow-vault-subtitle",
        text:
          "PIN хранится только на этом устройстве и не синхронизируется. " +
          "Подтвердите паролем. PIN — 4–8 цифр.",
      });
    });

    const form = contentEl.createEl("div", { cls: "shadow-vault-form" });

    this.inputPwd = createPasswordField({
      parent: form, label: "Текущий пароль", placeholder: "Введите пароль…", id: "pin-pwd",
    });

    const pinWrap = form.createEl("div", { cls: "sv-field" });
    pinWrap.createEl("label", { text: "PIN-код", attr: { for: "pin-new" } });
    this.inputPin = pinWrap.createEl("input", {
      type: "password",
      attr: { id: "pin-new", inputmode: "numeric", placeholder: "4–8 цифр", autocomplete: "off" },
    });

    const pinConfirmWrap = form.createEl("div", { cls: "sv-field" });
    pinConfirmWrap.createEl("label", { text: "Подтвердить PIN", attr: { for: "pin-confirm" } });
    this.inputPinConfirm = pinConfirmWrap.createEl("input", {
      type: "password",
      attr: { id: "pin-confirm", inputmode: "numeric", placeholder: "Повторите PIN", autocomplete: "off" },
    });

    this.errorEl = form.createEl("div", { cls: "shadow-vault-error sv-hidden" });

    this.btnSubmit = form.createEl("button", { cls: "shadow-vault-btn mod-cta", text: "Сохранить PIN" });
    this.btnSubmit.addEventListener("click", () => { void this.handleSubmit(); });

    for (const i of [this.inputPwd, this.inputPin, this.inputPinConfirm]) {
      i.addEventListener("keydown", (e) => { if (e.key === "Enter") void this.handleSubmit(); });
    }

    setTimeout(() => this.inputPwd.focus(), 50);
  }

  onClose(): void {
    this.contentEl.empty();
  }

  private async handleSubmit(): Promise<void> {
    if (this.busy) return;
    this.hideError();
    const pwd = this.inputPwd.value;
    const pin = this.inputPin.value;
    const pinConfirm = this.inputPinConfirm.value;

    if (!pwd) { this.showError("Введите текущий пароль."); return; }
    if (!/^\d{4,8}$/.test(pin)) { this.showError("PIN должен быть 4–8 цифр."); return; }
    if (pin !== pinConfirm) { this.showError("PIN не совпадает."); return; }

    this.setBusy(true);
    try {
      await this.plugin.setupPin(pwd, pin);
      this.inputPwd.value = this.inputPin.value = this.inputPinConfirm.value = "";
      new Notice("🔢 PIN установлен для этого устройства.", 4000);
      super.close();
    } catch (err) {
      // Снимаем busy ДО showError/focus — focus() на disabled input не сработает.
      this.setBusy(false);
      if (err instanceof PasswordError) {
        this.showError("Неверный пароль.");
        this.inputPwd.select();
        this.inputPwd.focus();
      } else {
        this.showError(err instanceof Error ? err.message : "Ошибка установки PIN.");
      }
    } finally {
      // Страховка: возвращаем форму в рабочее состояние при любом исходе.
      this.setBusy(false);
    }
  }

  /** Блокирует форму на время setupPin (PBKDF2 занимает секунды). */
  private setBusy(active: boolean): void {
    this.busy = active;
    this.btnSubmit.disabled = active;
    this.inputPwd.disabled = active;
    this.inputPin.disabled = active;
    this.inputPinConfirm.disabled = active;
  }

  private showError(msg: string): void {
    this.errorEl.setText(msg);
    this.errorEl.removeClass("sv-hidden");
  }
  private hideError(): void {
    this.errorEl.setText("");
    this.errorEl.addClass("sv-hidden");
  }
}
