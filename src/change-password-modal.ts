import { App, Modal, Notice } from "obsidian";
import { PasswordError } from "./auth-service";
import { createPasswordField } from "./password-field";
import { isValidEmail } from "./types";
import type ShadowVaultPlugin from "./main";

/**
 * Объединённая смена учётных данных: email И/ИЛИ пароль за ОДНУ пере-шифровку.
 *
 * Поля:
 *   - текущий пароль (для проверки, обязателен);
 *   - новый email (предзаполнен текущим; не меняя = оставить как есть);
 *   - новый пароль (пусто = не менять);
 *   - подтверждение нового пароля.
 *
 * Требование: хотя бы одно из (email, пароль) изменено, иначе ошибка.
 */
export class ChangeCredentialsModal extends Modal {
  private inputOld!: HTMLInputElement;
  private inputEmail!: HTMLInputElement;
  private inputNew!: HTMLInputElement;
  private inputConfirm!: HTMLInputElement;
  private btnSubmit!: HTMLButtonElement;
  private errorEl!: HTMLElement;
  private progressEl!: HTMLElement;

  /**
   * true — changeCredentials в процессе: закрытие модала запрещено,
   * повторный сабмит (Enter/кнопка) игнорируется.
   */
  private busy = false;

  private readonly currentEmail: string;

  constructor(app: App, private readonly plugin: ShadowVaultPlugin) {
    super(app);
    this.currentEmail = plugin.settings.email || "";
  }

  onOpen(): void {
    const { contentEl, modalEl } = this;
    modalEl.addClass("shadow-vault-modal");
    contentEl.empty();

    contentEl.createEl("div", { cls: "shadow-vault-header" }, (h) => {
      h.createEl("div", { cls: "shadow-vault-icon", text: "🔑" });
      h.createEl("h2", { cls: "shadow-vault-title", text: "Сменить email / пароль" });
      h.createEl("p", {
        cls: "shadow-vault-subtitle",
        text: "Все файлы будут пере-шифрованы новым ключом. Создайте резервную копию заранее.",
      });
    });

    const form = contentEl.createEl("div", { cls: "shadow-vault-form" });

    this.inputOld = createPasswordField({
      parent: form, label: "Текущий пароль", placeholder: "Введите текущий пароль…", id: "cc-old",
    });

    // Поле email (обычный текст, предзаполнено текущим значением).
    const emailWrap = form.createEl("div", { cls: "sv-field" });
    emailWrap.createEl("label", { text: "Новый email (оставьте как есть, чтобы не менять)", attr: { for: "cc-email" } });
    this.inputEmail = emailWrap.createEl("input", {
      type: "text",
      attr: { id: "cc-email", autocomplete: "off", spellcheck: "false" },
    });
    this.inputEmail.value = this.currentEmail;

    this.inputNew = createPasswordField({
      parent: form, label: "Новый пароль (пусто = не менять)", placeholder: "Введите новый пароль…", id: "cc-new",
    });
    this.inputConfirm = createPasswordField({
      parent: form, label: "Подтвердить новый пароль", placeholder: "Повторите новый пароль…", id: "cc-confirm",
    });

    this.errorEl = form.createEl("div", { cls: "shadow-vault-error sv-hidden" });

    this.progressEl = form.createEl("div", { cls: "shadow-vault-loading sv-hidden" }, (el) => {
      el.createEl("span", { cls: "sv-spinner" });
      el.createEl("span", { attr: { id: "cc-progress-text" }, text: " Пере-шифрование…" });
    });

    this.btnSubmit = form.createEl("button", {
      cls: "shadow-vault-btn mod-cta",
      text: "Сменить",
    });
    this.btnSubmit.addEventListener("click", () => { void this.handleSubmit(); });

    for (const input of [this.inputOld, this.inputEmail, this.inputNew, this.inputConfirm]) {
      input.addEventListener("keydown", (e) => { if (e.key === "Enter") void this.handleSubmit(); });
    }

    setTimeout(() => this.inputOld.focus(), 50);
  }

  /**
   * Запрещаем закрытие на время пере-шифровки (тот же приём, что в InitModal):
   * Escape, крестик и клик по фону в Obsidian сводятся к вызову close(),
   * поэтому одного перехвата здесь достаточно.
   */
  close(): void {
    if (this.busy) {
      this.showError("Идёт пере-шифрование — дождитесь завершения, окно закрывать нельзя.");
      return;
    }
    super.close();
  }

  onClose(): void {
    this.contentEl.empty();
  }

  private async handleSubmit(): Promise<void> {
    if (this.busy) return;
    this.hideError();

    const oldPwd = this.inputOld.value;
    const newEmail = this.inputEmail.value.trim();
    const newPwd = this.inputNew.value;
    const confirm = this.inputConfirm.value;

    if (!oldPwd) {
      this.showError("Введите текущий пароль.");
      this.inputOld.focus();
      return;
    }

    const emailChanged = newEmail.toLowerCase() !== this.currentEmail.trim().toLowerCase();
    const passwordChanged = newPwd.length > 0;

    if (!emailChanged && !passwordChanged) {
      this.showError("Измените email или пароль — иначе менять нечего.");
      return;
    }

    if (emailChanged && !isValidEmail(newEmail)) {
      this.showError("Некорректный email.");
      this.inputEmail.focus();
      return;
    }

    if (passwordChanged) {
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
    }

    this.setLoading(true);

    try {
      // newEmail — целевой email (если не менялся, передаём текущий — логика
      // changeCredentials сама нормализует). newPwd пустой = пароль не меняется.
      await this.plugin.changeCredentials(
        oldPwd,
        emailChanged ? newEmail : this.currentEmail,
        passwordChanged ? newPwd : "",
        (done, total) => {
          const textEl = this.progressEl.querySelector("#cc-progress-text");
          if (textEl) textEl.textContent = ` Пере-шифрование… ${done} / ${total}`;
        }
      );
      super.close();
    } catch (err) {
      // Снимаем блокировку ДО showError/focus — focus() на disabled input не сработает.
      this.setLoading(false);
      const message =
        err instanceof PasswordError
          ? err.message
          : "Ошибка пере-шифрования. Смотрите консоль разработчика.";
      if (!(err instanceof PasswordError)) {
        console.error("[ShadowVault] changeCredentials:", err);
      }
      if (!this.contentEl.isConnected) {
        // Edge: модал уже закрыт (например, выгрузка плагина) — DOM отсоединён,
        // showError никто не увидит. Сообщаем через Notice.
        new Notice(`⚠️ ${message}`, 8000);
        return;
      }
      this.showError(message);
      if (err instanceof PasswordError) {
        this.inputOld.select();
        this.inputOld.focus();
      }
    } finally {
      // Страховка: при любом исходе модал снова можно закрыть.
      this.setLoading(false);
    }
  }

  private setLoading(active: boolean): void {
    this.busy = active;
    this.btnSubmit.disabled = active;
    this.inputOld.disabled = active;
    this.inputEmail.disabled = active;
    this.inputNew.disabled = active;
    this.inputConfirm.disabled = active;

    if (active) this.progressEl.removeClass("sv-hidden");
    else this.progressEl.addClass("sv-hidden");
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
