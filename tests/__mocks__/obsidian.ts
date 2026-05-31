/**
 * Лёгкий runtime-мок пакета `obsidian` для jest.
 *
 * Реальный пакет obsidian — types-only (только obsidian.d.ts, без main),
 * поэтому в node-тестах он не резолвится. Здесь экспортируем минимальные
 * runtime-заглушки классов/функций, которые src/* используют как ЗНАЧЕНИЯ
 * (extends, new, instanceof, вызовы). Тип-онли импорты (App, Vault, ...)
 * стираются ts-jest и тут не нужны.
 */

export class Plugin {
  app: any;
  manifest: any;
  constructor(app?: any, manifest?: any) {
    this.app = app;
    this.manifest = manifest;
  }
  addCommand() {}
  addSettingTab() {}
  registerEvent() {}
  registerDomEvent() {}
  async loadData() {
    return {};
  }
  async saveData() {}
}

export class Modal {
  app: any;
  constructor(app?: any) {
    this.app = app;
  }
  open() {}
  close() {}
}

export class PluginSettingTab {
  app: any;
  plugin: any;
  constructor(app?: any, plugin?: any) {
    this.app = app;
    this.plugin = plugin;
  }
  display() {}
}

export class Setting {
  constructor(_containerEl?: any) {}
  setName() {
    return this;
  }
  setDesc() {
    return this;
  }
  addText() {
    return this;
  }
  addButton() {
    return this;
  }
  addToggle() {
    return this;
  }
}

export class Notice {
  constructor(_message?: string, _timeout?: number) {}
}

export class TAbstractFile {
  path = "";
}
export class TFile extends TAbstractFile {}
export class TFolder extends TAbstractFile {}

export const Platform = {
  isDesktopApp: false,
  isMobile: false,
};

export function normalizePath(p: string): string {
  return p;
}
