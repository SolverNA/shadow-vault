import { App, Modal } from "obsidian";
import { PasswordError } from "./auth-service";
import type ShadowVaultPlugin from "./main";

export class ChangePasswordModal extends Modal {
  private inputOld!: HTMLInputElement;
  private inputNew!: HTMLInputElement;
  private inputConfirm!: HTMLInputElement;
  private btnSubmit!: HTMLButtonElement;
  private errorEl!: HTMLElement;
  private progressEl!: HTMLElement;

  constructor(app: App, private readonly plugin: ShadowVaultPlugin) {
    super(app);
  }

  onOpen(): void {
    const { contentEl, modalEl } = this;
    modalEl.addClass("shadow-vault-modal");
    contentEl.empty();

    contentEl.createEl("div", { cls: "shadow-vault-header" }, (h) => {
      h.createEl("div", { cls: "shadow-vault-icon", text: "🔑" });
      h.createEl("h2", { cls: "shadow-vault-title", text: "Сменить пароль" });
      h.createEl("p", {
        cls: "shadow-vault-subtitle",
        text: "Все файлы будут пере-шифрованы. Создайте резервную копию заранее.",
      });
    });

    const form = contentEl.createEl("div", { cls: "shadow-vault-form" });

    this.inputOld     = this.createPasswordField(form, "Текущий пароль",       "Введите текущий пароль…",  "cp-old");
    this.inputNew     = this.createPasswordField(form, "Новый пароль",          "Введите новый пароль…",    "cp-new");
    this.inputConfirm = this.createPasswordField(form, "Подтвердить новый",     "Повторите новый пароль…",  "cp-confirm");

    this.errorEl = form.createEl("div", { cls: "shadow-vault-error sv-hidden" });

    this.progressEl = form.createEl("div", { cls: "shadow-vault-loading sv-hidden" }, (el) => {
      el.createEl("span", { cls: "sv-spinner" });
      el.createEl("span", { attr: { id: "cp-progress-text" }, text: " Пере-шифрование…" });
    });

    this.btnSubmit = form.createEl("button", {
      cls: "shadow-vault-btn mod-cta",
      text: "Сменить пароль",
    });
    this.btnSubmit.addEventListener("click", () => this.handleSubmit());

    for (const input of [this.inputOld, this.inputNew, this.inputConfirm]) {
      input.addEventListener("keydown", (e) => { if (e.key === "Enter") this.handleSubmit(); });
    }

    setTimeout(() => this.inputOld.focus(), 50);
  }

  onClose(): void {
    this.contentEl.empty();
  }

  private createPasswordField(
    parent: HTMLElement,
    label: string,
    placeholder: string,
    id: string
  ): HTMLInputElement {
    const wrapper = parent.createEl("div", { cls: "sv-field" });
    wrapper.createEl("label", { text: label, attr: { for: id } });

    const row   = wrapper.createEl("div", { cls: "sv-input-row" });
    const input = row.createEl("input", {
      type: "password",
      placeholder,
      attr: { id, autocomplete: "off", spellcheck: "false" },
    });

    const toggleBtn = row.createEl("button", {
      cls: "sv-toggle-password",
      attr: { type: "button", "aria-label": "Показать пароль" },
      text: "👁",
    });
    toggleBtn.addEventListener("click", () => {
      const hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      toggleBtn.setText(hidden ? "🙈" : "👁");
    });

    return input;
  }

  private async handleSubmit(): Promise<void> {
    this.hideError();

    const oldPwd  = this.inputOld.value;
    const newPwd  = this.inputNew.value;
    const confirm = this.inputConfirm.value;

    if (!oldPwd) {
      this.showError("Введите текущий пароль.");
      this.inputOld.focus();
      return;
    }
    if (newPwd.length < 8) {
      this.showError("Новый пароль слишком короткий. Минимум 8 символов.");
      this.inputNew.focus();
      return;
    }
    if (newPwd !== confirm) {
      this.showError("Новые пароли не совпадают.");
      this.inputConfirm.focus();
      return;
    }

    this.setLoading(true);

    try {
      await this.plugin.changePassword(oldPwd, newPwd, (done, total) => {
        const textEl = this.progressEl.querySelector("#cp-progress-text");
        if (textEl) textEl.textContent = ` Пере-шифрование… ${done} / ${total}`;
      });
      // changePassword блокирует хранилище сам — просто закрываем этот модал
      super.close();
    } catch (err) {
      this.setLoading(false);
      if (err instanceof PasswordError) {
        this.showError(err.message);
        this.inputOld.select();
        this.inputOld.focus();
      } else {
        this.showError("Ошибка пере-шифрования. Смотрите консоль разработчика.");
        console.error("[ShadowVault] changePassword:", err);
      }
    }
  }

  private setLoading(active: boolean): void {
    this.btnSubmit.disabled       = active;
    this.inputOld.disabled        = active;
    this.inputNew.disabled        = active;
    this.inputConfirm.disabled    = active;

    if (active) this.progressEl.removeClass("sv-hidden");
    else        this.progressEl.addClass("sv-hidden");
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
