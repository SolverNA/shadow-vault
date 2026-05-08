/**
 * Хелпер для создания поля ввода пароля с кнопкой показать/скрыть.
 * Используется обоими модалами (InitModal, ChangePasswordModal).
 */

export interface PasswordFieldOptions {
  parent:      HTMLElement;
  label:       string;
  placeholder: string;
  id:          string;
}

export function createPasswordField(opts: PasswordFieldOptions): HTMLInputElement {
  const { parent, label, placeholder, id } = opts;

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
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    toggleBtn.setText(isHidden ? "🙈" : "👁");
  });

  return input;
}
