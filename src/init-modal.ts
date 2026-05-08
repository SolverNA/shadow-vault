/**
 * InitModal — модальное окно ввода пароля для ShadowVault.
 *
 * Блокирует загрузку рабочей области Obsidian до успешного ввода пароля.
 * Закрыть окно без ввода пароля нельзя: клик вне окна и Escape перехватываются.
 *
 * UI-поведение:
 *   - Первый запуск: заголовок "Создать хранилище", поле "Подтвердить пароль"
 *   - Повторный вход: заголовок "Разблокировать хранилище"
 *   - Индикатор загрузки во время ~300 мс деривации ключа
 *   - Кнопка показа/скрытия пароля
 *   - Отображение ошибки без закрытия окна
 */

import { App, Modal } from "obsidian";
import { PluginSettings } from "./types";
import { AuthService, AuthResult, PasswordError, SettingsCorruptedError, SaveSettingsFn } from "./auth-service";
import { createPasswordField } from "./password-field";

export type UnlockCallback = (result: AuthResult) => void;

export class InitModal extends Modal {
  private settings: PluginSettings;
  private saveFn: SaveSettingsFn;
  private onUnlock: UnlockCallback;
  private authService: AuthService;

  // DOM-элементы, сохраняем ссылки для управления состоянием
  private inputPassword!: HTMLInputElement;
  private inputConfirm!: HTMLInputElement | null;
  private btnSubmit!: HTMLButtonElement;
  private errorEl!: HTMLElement;
  private loadingEl!: HTMLElement;

  private isFirstRun: boolean;
  /** Разрешить закрытие только после успешного ввода пароля */
  private allowClose = false;

  constructor(
    app: App,
    settings: PluginSettings,
    saveFn: SaveSettingsFn,
    onUnlock: UnlockCallback
  ) {
    super(app);
    this.settings = settings;
    this.saveFn = saveFn;
    this.onUnlock = onUnlock;
    this.authService = new AuthService();
    this.isFirstRun = settings.saltHex === null;
  }

  onOpen(): void {
    const { contentEl, modalEl } = this;

    // Запрещаем закрытие по Escape и клику вне окна —
    // без пароля плагин не может начать работу
    this.scope.register([], "Escape", () => {
      this.showError("Введите пароль для продолжения.");
      return false;
    });

    modalEl.addClass("shadow-vault-modal");
    contentEl.empty();

    // ── Шапка ────────────────────────────────────────────────────────────
    contentEl.createEl("div", { cls: "shadow-vault-header" }, (header) => {
      header.createEl("div", { cls: "shadow-vault-icon", text: "🔐" });
      header.createEl("h2", {
        cls: "shadow-vault-title",
        text: this.isFirstRun
          ? "Создать зашифрованное хранилище"
          : "Разблокировать хранилище",
      });
      header.createEl("p", {
        cls: "shadow-vault-subtitle",
        text: this.isFirstRun
          ? "Придумайте надёжный пароль. Восстановить его будет невозможно."
          : "Введите пароль для расшифровки хранилища.",
      });
    });

    // ── Форма ─────────────────────────────────────────────────────────────
    const form = contentEl.createEl("div", { cls: "shadow-vault-form" });

    // Поле пароля
    this.inputPassword = createPasswordField({
      parent: form,
      label: "Пароль",
      placeholder: "Введите пароль…",
      id: "sv-password",
    });

    // Поле подтверждения — только при первом запуске
    if (this.isFirstRun) {
      this.inputConfirm = createPasswordField({
        parent: form,
        label: "Подтвердить пароль",
        placeholder: "Повторите пароль…",
        id: "sv-confirm",
      });
    } else {
      this.inputConfirm = null;
    }

    // Блок ошибки (скрыт по умолчанию)
    this.errorEl = form.createEl("div", { cls: "shadow-vault-error sv-hidden" });

    // Индикатор загрузки (скрыт по умолчанию)
    this.loadingEl = form.createEl("div", { cls: "shadow-vault-loading sv-hidden" }, (el) => {
      el.createEl("span", { cls: "sv-spinner" });
      el.createEl("span", { text: " Деривация ключа…" });
    });

    // Кнопка подтверждения
    this.btnSubmit = form.createEl("button", {
      cls: "shadow-vault-btn mod-cta",
      text: this.isFirstRun ? "Создать хранилище" : "Разблокировать",
    });
    this.btnSubmit.addEventListener("click", () => { void this.handleSubmit(); });

    // Enter в любом поле → submit
    this.inputPassword.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.handleSubmit();
    });
    this.inputConfirm?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.handleSubmit();
    });

    // Фокус на первом поле после открытия
    setTimeout(() => this.inputPassword.focus(), 50);
  }

  /** Запрещаем любое закрытие (фон, Esc, внешний вызов) пока пароль не принят */
  close(): void {
    if (this.allowClose) super.close();
  }

  onClose(): void {
    this.contentEl.empty();
  }

  // ─────────────────────────────────────────────
  // Приватные методы
  // ─────────────────────────────────────────────

  /**
   * Обработчик отправки формы.
   * Валидирует поля, запускает AuthService, обрабатывает ошибки.
   */
  private async handleSubmit(): Promise<void> {
    this.hideError();
    const password = this.inputPassword.value;

    // Валидация при первом запуске: пароли должны совпасть
    if (this.isFirstRun) {
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

      // Очищаем поля из памяти DOM как можно раньше
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
    this.errorEl.setText(message);
    this.errorEl.removeClass("sv-hidden");
  }

  private hideError(): void {
    this.errorEl.setText("");
    this.errorEl.addClass("sv-hidden");
  }
}
