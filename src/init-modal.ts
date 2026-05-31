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
import { PluginSettings, isValidEmail } from "./types";
import { AuthService, AuthResult, PasswordError, SettingsCorruptedError, SaveSettingsFn } from "./auth-service";
import { createPasswordField } from "./password-field";
import { PinStore, PinError, PinLockoutError } from "./pin-store";
import { createCryptoEngine } from "./crypto/factory";

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

  private pinStore: PinStore;
  /** true — на экране разблокировки показан ввод PIN вместо пароля */
  private pinMode = false;

  // DOM-элементы — устанавливаются в render()
  private inputEmail: HTMLInputElement | null = null;
  private inputPassword: HTMLInputElement | null = null;
  private inputConfirm: HTMLInputElement | null = null;
  private inputPin: HTMLInputElement | null = null;
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
    this.pinStore = new PinStore();
    // Если на устройстве настроен PIN — по умолчанию предлагаем вход по PIN.
    this.pinMode = this.pinStore.isPinSet() && settings.verificationBlob !== null && !orphanVault;
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
    this.inputEmail = null;
    this.inputPassword = null;
    this.inputConfirm = null;
    this.inputPin = null;
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
        "Укажите email и придумайте надёжный пароль. Восстановить пароль будет невозможно.");
      this.renderCreateForm(contentEl);
    } else if (this.pinMode) {
      this.renderHeader(contentEl, "🔢", "Вход по PIN",
        "Введите PIN-код для быстрого входа.");
      this.renderPinForm(contentEl);
    } else {
      this.renderHeader(contentEl, "🔐", "Разблокировать хранилище",
        "Введите пароль для расшифровки хранилища.");
      this.renderUnlockForm(contentEl);
    }
  }

  /** Создаёт поле email (текстовое, не пароль). */
  private createEmailField(parent: HTMLElement, value: string, readOnly: boolean): HTMLInputElement {
    const wrapper = parent.createEl("div", { cls: "sv-field" });
    wrapper.createEl("label", { text: "Email", attr: { for: "sv-email" } });
    const input = wrapper.createEl("input", {
      type: "email",
      attr: {
        id: "sv-email",
        placeholder: "you@example.com",
        autocomplete: "off",
        spellcheck: "false",
        ...(readOnly ? { readonly: "true" } : {}),
      },
    });
    input.value = value;
    return input;
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

  /** Форма восстановления: email + пароль, без подтверждения */
  private renderRestoreForm(parent: HTMLElement): void {
    const form = parent.createEl("div", { cls: "shadow-vault-form" });

    this.inputEmail = this.createEmailField(form, this.settings.email || "", false);

    this.inputPassword = createPasswordField({
      parent: form,
      label: "Пароль",
      placeholder: "Введите пароль хранилища…",
      id: "sv-password",
    });

    this.renderSharedControls(form);
    if (!this.btnSubmit) return;
    this.btnSubmit.textContent = "Восстановить";

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

  /** Форма создания хранилища: email + пароль + подтверждение */
  private renderCreateForm(parent: HTMLElement): void {
    const form = parent.createEl("div", { cls: "shadow-vault-form" });

    this.inputEmail = this.createEmailField(form, this.settings.email || "", false);

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
    if (!this.btnSubmit) return;
    this.btnSubmit.textContent = "Создать хранилище";

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

  /** Форма разблокировки: email (read-only, если сохранён) + пароль */
  private renderUnlockForm(parent: HTMLElement): void {
    const form = parent.createEl("div", { cls: "shadow-vault-form" });

    const hasSavedEmail = !!this.settings.email;
    this.inputEmail = this.createEmailField(form, this.settings.email || "", hasSavedEmail);

    this.inputPassword = createPasswordField({
      parent: form,
      label: "Пароль",
      placeholder: "Введите пароль…",
      id: "sv-password",
    });

    this.renderSharedControls(form);
    if (!this.btnSubmit) return;
    this.btnSubmit.textContent = "Разблокировать";

    this.inputPassword.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.handleSubmit();
    });

    // Ссылка на вход по PIN (если на устройстве он настроен).
    if (this.pinStore.isPinSet()) {
      const pinLink = form.createEl("button", {
        cls: "shadow-vault-btn sv-btn-back",
        text: "🔢 Войти по PIN",
      });
      pinLink.addEventListener("click", () => {
        this.pinMode = true;
        this.render();
      });
    }

    setTimeout(() => (hasSavedEmail ? this.inputPassword : this.inputEmail)?.focus(), 50);
  }

  /** Форма входа по PIN. */
  private renderPinForm(parent: HTMLElement): void {
    const form = parent.createEl("div", { cls: "shadow-vault-form" });

    const wrapper = form.createEl("div", { cls: "sv-field" });
    wrapper.createEl("label", { text: "PIN-код", attr: { for: "sv-pin" } });
    this.inputPin = wrapper.createEl("input", {
      type: "password",
      attr: {
        id: "sv-pin",
        inputmode: "numeric",
        placeholder: "Введите PIN…",
        autocomplete: "off",
      },
    });

    this.renderSharedControls(form);
    if (!this.btnSubmit) return;
    this.btnSubmit.textContent = "Войти";

    this.inputPin.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.handlePinSubmit();
    });
    // Перенаправляем submit-кнопку на PIN-обработчик.
    this.btnSubmit.onclick = () => { void this.handlePinSubmit(); };

    const pwdLink = form.createEl("button", {
      cls: "shadow-vault-btn sv-btn-back",
      text: "Войти по паролю",
    });
    pwdLink.addEventListener("click", () => {
      this.pinMode = false;
      this.render();
    });

    setTimeout(() => this.inputPin?.focus(), 50);
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
    // Email: из поля ввода (если редактируемое) либо из сохранённых настроек.
    const email = (this.inputEmail?.value ?? this.settings.email ?? "").trim();

    const isCreateMode =
      (!this.orphanVault && this.settings.verificationBlob === null) ||
      (this.orphanVault && this.orphanScreen === "create");

    // Мягкая валидация email на всех экранах ввода email.
    if (this.inputEmail && !this.inputEmail.hasAttribute("readonly")) {
      if (!isValidEmail(email)) {
        this.showError("Введите корректный email (например you@example.com).");
        this.inputEmail.focus();
        return;
      }
    }

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
        email,
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

  /**
   * Вход по PIN: разворачивает локальный wrapped-ключ, строит движок из
   * сырого мастер-ключа и отдаёт его как AuthResult (без пароля).
   */
  private async handlePinSubmit(): Promise<void> {
    if (!this.inputPin || !this.btnSubmit || !this.errorEl) return;
    this.hideError();
    const pin = this.inputPin.value;
    if (!pin.trim()) {
      this.showError("Введите PIN.");
      return;
    }

    this.setLoading(true);
    let rawKey: Uint8Array | null = null;
    try {
      rawKey = await this.pinStore.unlockWithPin(pin);

      // Строим движок из сырого мастер-ключа (минуя PBKDF2 из пароля).
      const engine = createCryptoEngine();
      await Promise.resolve((engine as { loadRawKey: (k: Uint8Array) => unknown }).loadRawKey(rawKey));

      const result: AuthResult = {
        engine,
        password: null,
        email: this.settings.email,
        rawKey: rawKey.slice(),
        isFirstRun: false,
      };

      this.inputPin.value = "";
      this.allowClose = true;
      this.close();
      this.onUnlock(result);
    } catch (err) {
      this.setLoading(false);
      if (err instanceof PinLockoutError) {
        // PIN сброшен → возвращаемся к вводу пароля.
        this.pinMode = false;
        this.render();
        this.showError(`⚠️ ${err.message}`);
      } else if (err instanceof PinError) {
        this.showError(err.message);
        this.inputPin.select();
        this.inputPin.focus();
      } else {
        this.showError("Ошибка входа по PIN. Войдите по паролю.");
        console.error("[ShadowVault] PIN unlock ошибка:", err);
        this.pinMode = false;
        this.render();
      }
    }
  }

  private setLoading(active: boolean): void {
    if (!this.btnSubmit || !this.loadingEl) return;
    this.btnSubmit.disabled = active;
    if (this.inputPassword) this.inputPassword.disabled = active;
    if (this.inputConfirm) this.inputConfirm.disabled = active;
    if (this.inputEmail) this.inputEmail.disabled = active;
    if (this.inputPin) this.inputPin.disabled = active;

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
