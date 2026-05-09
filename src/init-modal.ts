/**
 * InitModal — модальное окно ввода пароля для ShadowVault.
 *
 * Блокирует загрузку рабочей области Obsidian до успешного ввода пароля.
 * Закрыть окно без ввода пароля нельзя: клик вне окна и Escape перехватываются.
 *
 * Экраны:
 *   - first-run     : обычный первый запуск (пароль + подтверждение)
 *   - unlock        : обычный повторный вход (только пароль)
 *   - orphan-choice : .enc найдены, data.json утерян — выбор: восстановить / создать заново
 *   - orphan-restore: восстановление паролем (одно поле, без подтверждения)
 *   - orphan-create : создать заново после orphan (стандартная форма с подтверждением)
 *
 * Соль не используется. С точки зрения AuthService orphan-restore и orphan-create
 * идентичны (первый запуск, генерация verificationBlob) — разница только в UX:
 * восстановление принимает короткий пароль без подтверждения.
 */

import { App, Modal } from "obsidian";
import { PluginSettings } from "./types";
import { AuthService, AuthResult, PasswordError, SettingsCorruptedError, SaveSettingsFn } from "./auth-service";
import { createPasswordField } from "./password-field";

export type UnlockCallback = (result: AuthResult) => void;

type OrphanScreen = "choice" | "restore" | "create";

export class InitModal extends Modal {
  private settings: PluginSettings;
  private saveFn: SaveSettingsFn;
  private onUnlock: UnlockCallback;
  private authService: AuthService;

  private orphanVault: boolean;
  /** Текущий экран (только для orphan-режима) */
  private orphanScreen: OrphanScreen = "choice";

  // DOM-элементы — устанавливаются в render()
  private inputPassword: HTMLInputElement | null = null;
  private inputConfirm: HTMLInputElement | null = null;
  private btnSubmit: HTMLButtonElement | null = null;
  private errorEl: HTMLElement | null = null;
  private loadingEl: HTMLElement | null = null;

  /** Разрешить закрытие только после успешного ввода пароля */
  private allowClose = false;

  constructor(
    app: App,
    settings: PluginSettings,
    saveFn: SaveSettingsFn,
    onUnlock: UnlockCallback,
    orphanVault = false
  ) {
    super(app);
    this.settings = settings;
    this.saveFn = saveFn;
    this.onUnlock = onUnlock;
    this.authService = new AuthService();
    this.orphanVault = orphanVault;
  }

  onOpen(): void {
    const { modalEl } = this;

    this.scope.register([], "Escape", () => {
      this.showError("Введите пароль для продолжения.");
      return false;
    });

    modalEl.addClass("shadow-vault-modal");
    modalEl.querySelectorAll(".modal-close-button").forEach((el) => el.remove());

    this.render();
  }

  /** Запрещаем любое закрытие пока пароль не принят */
  close(): void {
    if (this.allowClose) super.close();
  }

  onClose(): void {
    this.contentEl.empty();
  }

  // ─────────────────────────────────────────────
  // Rendering
  // ─────────────────────────────────────────────

  private render(): void {
    const { contentEl } = this;
    contentEl.empty();

    // Сброс DOM-refs
    this.inputPassword = null;
    this.inputConfirm = null;
    this.btnSubmit = null;
    this.errorEl = null;
    this.loadingEl = null;

    if (this.orphanVault) {
      if (this.orphanScreen === "choice") {
        this.renderOrphanChoice(contentEl);
        return;
      }
      if (this.orphanScreen === "restore") {
        this.renderHeader(contentEl, "🔑", "Восстановить хранилище",
          "Введите пароль, которым было создано хранилище. Если он верный — старые файлы расшифруются автоматически.");
        this.renderRestoreForm(contentEl);
        return;
      }
      // orphan-create
      this.renderHeader(contentEl, "🔐", "Создать новое хранилище",
        "Существующие .enc файлы останутся на диске, но станут НЕДОСТУПНЫ без старого пароля.");
      this.renderCreateForm(contentEl);
      return;
    }

    if (this.settings.verificationBlob === null) {
      this.renderHeader(contentEl, "🔐", "Создать зашифрованное хранилище",
        "Придумайте надёжный пароль. Восстановить его будет невозможно.");
      this.renderCreateForm(contentEl);
    } else {
      this.renderHeader(contentEl, "🔐", "Разблокировать хранилище",
        "Введите пароль для расшифровки хранилища.");
      this.renderUnlockForm(contentEl);
    }
  }

  private renderHeader(parent: HTMLElement, icon: string, title: string, subtitle: string): void {
    parent.createEl("div", { cls: "shadow-vault-header" }, (header) => {
      header.createEl("div", { cls: "shadow-vault-icon", text: icon });
      header.createEl("h2", { cls: "shadow-vault-title", text: title });
      header.createEl("p", { cls: "shadow-vault-subtitle", text: subtitle });
    });
  }

  /** Дисклеймер с двумя кнопками — orphan vault detected */
  private renderOrphanChoice(parent: HTMLElement): void {
    parent.createEl("div", { cls: "shadow-vault-header" }, (header) => {
      header.createEl("div", { cls: "shadow-vault-icon", text: "⚠️" });
      header.createEl("h2", {
        cls: "shadow-vault-title",
        text: "Хранилище зашифровано, но настройки утеряны",
      });
      header.createEl("p", {
        cls: "shadow-vault-subtitle",
        text:
          "В хранилище найдены зашифрованные файлы (.enc), но файл настроек " +
          "(data.json) отсутствует. Если вы помните пароль — выберите «Восстановить». " +
          "Если пароль утерян — создайте новое хранилище (старые файлы станут недоступны).",
      });
    });

    const choiceEl = parent.createEl("div", { cls: "shadow-vault-choice" });

    const btnRestore = choiceEl.createEl("button", {
      cls: "shadow-vault-btn mod-cta",
      text: "Восстановить хранилище",
    });
    btnRestore.addEventListener("click", () => {
      this.orphanScreen = "restore";
      this.render();
    });

    const btnCreate = choiceEl.createEl("button", {
      cls: "shadow-vault-btn sv-btn-secondary",
      text: "Создать хранилище заново",
    });
    btnCreate.addEventListener("click", () => {
      this.orphanScreen = "create";
      this.render();
    });
  }

  /** Форма восстановления: одно поле пароля, без подтверждения */
  private renderRestoreForm(parent: HTMLElement): void {
    const form = parent.createEl("div", { cls: "shadow-vault-form" });

    this.inputPassword = createPasswordField({
      parent: form,
      label: "Пароль",
      placeholder: "Введите пароль хранилища…",
      id: "sv-password",
    });

    this.renderSharedControls(form);
    this.btnSubmit!.textContent = "Восстановить";

    this.inputPassword.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.handleSubmit();
    });

    const backBtn = form.createEl("button", {
      cls: "shadow-vault-btn sv-btn-back",
      text: "← Назад",
    });
    backBtn.addEventListener("click", () => {
      this.orphanScreen = "choice";
      this.render();
    });

    setTimeout(() => this.inputPassword?.focus(), 50);
  }

  /** Форма создания хранилища: пароль + подтверждение */
  private renderCreateForm(parent: HTMLElement): void {
    const form = parent.createEl("div", { cls: "shadow-vault-form" });

    this.inputPassword = createPasswordField({
      parent: form,
      label: "Пароль",
      placeholder: "Придумайте надёжный пароль…",
      id: "sv-password",
    });
    this.inputConfirm = createPasswordField({
      parent: form,
      label: "Подтвердить пароль",
      placeholder: "Повторите пароль…",
      id: "sv-confirm",
    });

    this.renderSharedControls(form);
    this.btnSubmit!.textContent = "Создать хранилище";

    this.inputPassword.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.handleSubmit();
    });
    this.inputConfirm.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.handleSubmit();
    });

    // В orphan-create показываем ссылку «Назад»
    if (this.orphanVault) {
      const backBtn = form.createEl("button", {
        cls: "shadow-vault-btn sv-btn-back",
        text: "← Назад",
      });
      backBtn.addEventListener("click", () => {
        this.orphanScreen = "choice";
        this.render();
      });
    }

    setTimeout(() => this.inputPassword?.focus(), 50);
  }

  /** Форма разблокировки: только пароль */
  private renderUnlockForm(parent: HTMLElement): void {
    const form = parent.createEl("div", { cls: "shadow-vault-form" });

    this.inputPassword = createPasswordField({
      parent: form,
      label: "Пароль",
      placeholder: "Введите пароль…",
      id: "sv-password",
    });

    this.renderSharedControls(form);
    this.btnSubmit!.textContent = "Разблокировать";

    this.inputPassword.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.handleSubmit();
    });

    setTimeout(() => this.inputPassword?.focus(), 50);
  }

  /** Общие элементы всех форм: ошибка, загрузка, кнопка submit */
  private renderSharedControls(form: HTMLElement): void {
    this.errorEl = form.createEl("div", { cls: "shadow-vault-error sv-hidden" });

    this.loadingEl = form.createEl("div", { cls: "shadow-vault-loading sv-hidden" }, (el) => {
      el.createEl("span", { cls: "sv-spinner" });
      el.createEl("span", { text: " Деривация ключа…" });
    });

    this.btnSubmit = form.createEl("button", {
      cls: "shadow-vault-btn mod-cta",
      text: "OK",
    });
    this.btnSubmit.addEventListener("click", () => { void this.handleSubmit(); });
  }

  // ─────────────────────────────────────────────
  // Обработка отправки
  // ─────────────────────────────────────────────

  private async handleSubmit(): Promise<void> {
    if (!this.inputPassword || !this.btnSubmit || !this.errorEl) return;
    this.hideError();
    const password = this.inputPassword.value;

    const isCreateMode =
      (!this.orphanVault && this.settings.verificationBlob === null) ||
      (this.orphanVault && this.orphanScreen === "create");

    // В create-режиме: пароли должны совпасть, минимум 8 символов
    if (isCreateMode) {
      const confirm = this.inputConfirm?.value ?? "";
      if (password !== confirm) {
        this.showError("Пароли не совпадают. Проверьте ввод.");
        this.inputConfirm?.focus();
        return;
      }
      if (password.length < 8) {
        this.showError("Пароль слишком короткий. Минимум 8 символов.");
        this.inputPassword.focus();
        return;
      }
    }

    this.setLoading(true);

    try {
      const result = await this.authService.authenticate(
        password,
        this.settings,
        this.saveFn
      );

      this.inputPassword.value = "";
      if (this.inputConfirm) this.inputConfirm.value = "";

      this.allowClose = true;
      this.close();
      this.onUnlock(result);
    } catch (err) {
      this.setLoading(false);

      if (err instanceof PasswordError) {
        this.showError(err.message);
        this.inputPassword.select();
        this.inputPassword.focus();
      } else if (err instanceof SettingsCorruptedError) {
        this.showError(`⚠️ ${err.message}`);
      } else {
        this.showError("Неизвестная ошибка. Смотрите консоль разработчика.");
        console.error("[ShadowVault] InitModal ошибка:", err);
      }
    }
  }

  private setLoading(active: boolean): void {
    if (!this.btnSubmit || !this.loadingEl || !this.inputPassword) return;
    this.btnSubmit.disabled = active;
    this.inputPassword.disabled = active;
    if (this.inputConfirm) this.inputConfirm.disabled = active;

    if (active) {
      this.loadingEl.removeClass("sv-hidden");
    } else {
      this.loadingEl.addClass("sv-hidden");
    }
  }

  private showError(message: string): void {
    if (!this.errorEl) return;
    this.errorEl.setText(message);
    this.errorEl.removeClass("sv-hidden");
  }

  private hideError(): void {
    if (!this.errorEl) return;
    this.errorEl.setText("");
    this.errorEl.addClass("sv-hidden");
  }
}
