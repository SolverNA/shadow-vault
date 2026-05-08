/**
 * QueueIntegration — Obsidian-специфичный слой над QueueManager.
 *
 * Ответственность:
 *   - Создать элемент статус-бара и обновлять его при каждом тике прогресса.
 *   - Подписаться на app.workspace.on('file-open') для приоритизации файлов.
 *   - Показывать Notice-предупреждение при попытке глобального поиска
 *     пока расшифровка не завершена.
 *   - Отписаться от всех событий при teardown().
 *
 * Этот класс намеренно тонкий: вся логика в QueueManager.
 * Здесь только "провода" между QueueManager и Obsidian API.
 */

import { App, Events, Notice, Plugin, TFile } from "obsidian";
import { QueueManager, QueueProgress } from "./queue-manager";
import { ShadowVaultManager } from "./shadow-vault-manager";

export class QueueIntegration {
  private statusBarEl: HTMLElement | null = null;
  private unsubscribeProgress: (() => void) | null = null;
  private unsubscribeComplete: (() => void) | null = null;

  constructor(
    private readonly app:     App,
    private readonly plugin:  Plugin,
    private readonly queue:   QueueManager,
    private readonly manager: ShadowVaultManager
  ) {}

  /**
   * Инициализирует интеграцию:
   *   - Сканирует оригинальное хранилище и загружает файлы в очередь.
   *   - Создаёт элемент статус-бара.
   *   - Регистрирует хук file-open.
   *   - Запускает фоновую расшифровку (не блокирует UI).
   */
  async setup(): Promise<void> {
    // ── Статус-бар ─────────────────────────────────────────────────────
    this.statusBarEl = this.plugin.addStatusBarItem();
    this.statusBarEl.addClass("shadow-vault-status");

    // Сразу показываем начальное состояние до старта очереди
    this.updateStatusBar({ total: 0, completed: 0, failed: 0, pending: 0, inProgress: 0, percentage: 0, isComplete: false });

    // ── Подписки на прогресс ────────────────────────────────────────────
    this.unsubscribeProgress = this.queue.onProgress((p) => this.updateStatusBar(p));
    this.unsubscribeComplete = this.queue.onComplete(() => {
      this.updateStatusBar(this.queue.getProgress());
      new Notice("🔐 Shadow Vault: хранилище полностью расшифровано, поиск доступен.");
    });

    // ── Хук file-open: приоритизация открываемых файлов ────────────────
    // Регистрируем через plugin.registerEvent, чтобы Obsidian сам снял хук при unload
    this.plugin.registerEvent(
      this.app.workspace.on("file-open", (file: TFile | null) => {
        if (!file) return;

        if (!this.queue.isDecrypted(file.path) && !this.queue.isInProgress(file.path)) {
          // Файл ещё не расшифрован — двигаем в начало очереди
          this.queue.prioritize(file.path);
          // ensureDecrypted вызовется из patchedRead при фактическом чтении файла —
          // приоритизация только ускоряет фоновую pre-fetch расшифровку
        }
      })
    );

    // ── Предупреждение при поиске пока идёт расшифровка ─────────────────
    // Перехватываем команду глобального поиска Obsidian
    this.plugin.registerEvent(
      (this.app.workspace as unknown as Events).on("search:open", () => {
        if (!this.queue.getProgress().isComplete) {
          const p = this.queue.getProgress();
          new Notice(
            `⚠️ Shadow Vault: результаты поиска могут быть неполными.\n` +
            `Расшифровано ${p.completed} из ${p.total} файлов (${p.percentage}%).`,
            6000
          );
        }
      })
    );

    // ── Сканирование и запуск фоновой расшифровки ───────────────────────
    const allPaths = await this.scanEncryptedFiles();
    this.queue.enqueue(allPaths);

    // Не await — очередь работает в фоне
    this.queue.start().catch((err) => {
      console.error("[ShadowVault] Критическая ошибка очереди расшифровки:", err);
    });
  }

  /**
   * Останавливает все процессы интеграции.
   * Вызывается при корректном завершении сессии (Шаг 5, SessionManager).
   */
  teardown(): void {
    this.queue.stop();
    this.unsubscribeProgress?.();
    this.unsubscribeComplete?.();
    this.statusBarEl?.remove();
    this.statusBarEl = null;
  }

  /** Возвращает true если все файлы расшифрованы (поиск безопасен) */
  isSearchSafe(): boolean {
    return this.queue.getProgress().isComplete;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Приватные методы
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Рекурсивно обходит оригинальное хранилище и собирает список
   * всех файлов, которые нужно расшифровать (не .obsidian, не папки).
   *
   * Использует list() адаптера — который уже пропатчен нашим менеджером
   * и читает структуру из originalRoot.
   */
  private async scanEncryptedFiles(dir = ""): Promise<string[]> {
    const result: string[] = [];
    try {
      const { files, folders } = await this.app.vault.adapter.list(dir);
      result.push(...files.filter((f) => !this.manager.isBypassPath(f)));
      for (const folder of folders) {
        if (this.manager.isBypassPath(folder)) continue;
        const sub = await this.scanEncryptedFiles(folder);
        result.push(...sub);
      }
    } catch (err) {
      console.warn(`[ShadowVault] Не удалось просканировать директорию "${dir}":`, err);
    }
    return result;
  }

  /** Обновляет текст в статус-баре Obsidian */
  private updateStatusBar(p: QueueProgress): void {
    if (!this.statusBarEl) return;

    if (p.total === 0) {
      this.statusBarEl.setText("🔐 Shadow Vault");
      return;
    }

    if (p.isComplete) {
      this.statusBarEl.setText(`🔐 ${p.completed}/${p.total}`);
      this.statusBarEl.setAttr("title", "Shadow Vault: хранилище расшифровано");
      return;
    }

    // Формат: 🛡️ Расшифровка хранилища: 450/1200 (37%)  — из ТЗ п.6
    this.statusBarEl.setText(
      `🛡️ Расшифровка хранилища: ${p.completed}/${p.total} (${p.percentage}%)`
    );

    if (p.failed > 0) {
      this.statusBarEl.setAttr(
        "title",
        `ShadowVault: ${p.failed} файл(ов) не удалось расшифровать`
      );
    }
  }
}
