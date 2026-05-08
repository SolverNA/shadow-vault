/**
 * Простой модал подтверждения с двумя кнопками — замена нативному window.confirm().
 * Obsidian запрещает confirm() в плагинах (eslint правило).
 */

import { App, Modal, Setting } from "obsidian";

export class ConfirmModal extends Modal {
  constructor(
    app: App,
    private readonly message: string,
    private readonly onChoose: (confirmed: boolean) => void
  ) {
    super(app);
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.createEl("p", { text: this.message });
    new Setting(contentEl)
      .addButton((btn) =>
        btn.setButtonText("Подтвердить").setWarning().onClick(() => {
          this.onChoose(true);
          this.close();
        })
      )
      .addButton((btn) =>
        btn.setButtonText("Отмена").onClick(() => {
          this.onChoose(false);
          this.close();
        })
      );
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
