/**
 * Тесты busy-паттерна модалок: повторный сабмит во время незавершённой
 * операции игнорируется, поля блокируются, модал смены учётных данных
 * нельзя закрыть во время пере-шифровки.
 *
 * DOM не поднимается: onOpen не вызывается, вместо реальных элементов —
 * лёгкие заглушки (мок Modal из tests/__mocks__/obsidian.ts минимальный).
 */

import { SetPinModal } from "../src/set-pin-modal";
import { ChangeCredentialsModal } from "../src/change-password-modal";
import { Modal } from "obsidian";

interface FakeInput {
  value: string;
  disabled: boolean;
  focus: jest.Mock;
  select: jest.Mock;
}

function fakeInput(value: string): FakeInput {
  return { value, disabled: false, focus: jest.fn(), select: jest.fn() };
}

function fakeErrorEl() {
  return { setText: jest.fn(), addClass: jest.fn(), removeClass: jest.fn() };
}

/** Отложенный промис: операция «висит», пока тест не вызовет resolve/reject. */
function deferred<T = void>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("SetPinModal — busy-флаг", () => {
  function makeModal(setupPin: jest.Mock) {
    const modal = new SetPinModal({} as never, { setupPin } as never);
    const m = modal as unknown as {
      inputPwd: FakeInput;
      inputPin: FakeInput;
      inputPinConfirm: FakeInput;
      btnSubmit: { disabled: boolean };
      errorEl: ReturnType<typeof fakeErrorEl>;
      busy: boolean;
      handleSubmit(): Promise<void>;
    };
    m.inputPwd = fakeInput("correct-password");
    m.inputPin = fakeInput("1234");
    m.inputPinConfirm = fakeInput("1234");
    m.btnSubmit = { disabled: false };
    m.errorEl = fakeErrorEl();
    return m;
  }

  test("повторный сабмит во время setupPin не запускает вторую операцию", async () => {
    const d = deferred();
    const setupPin = jest.fn(() => d.promise);
    const m = makeModal(setupPin);

    const first = m.handleSubmit();
    expect(setupPin).toHaveBeenCalledTimes(1);
    expect(m.busy).toBe(true);
    // Поля заблокированы на время операции.
    expect(m.inputPwd.disabled).toBe(true);
    expect(m.inputPin.disabled).toBe(true);
    expect(m.inputPinConfirm.disabled).toBe(true);
    expect(m.btnSubmit.disabled).toBe(true);

    // Повторный Enter / клик по кнопке — игнорируется.
    await m.handleSubmit();
    expect(setupPin).toHaveBeenCalledTimes(1);

    d.resolve();
    await first;
    expect(m.busy).toBe(false);
  });

  test("после ошибки форма разблокируется и сабмит снова возможен", async () => {
    const d = deferred();
    const setupPin = jest.fn(() => d.promise);
    const m = makeModal(setupPin);

    const first = m.handleSubmit();
    d.reject(new Error("boom"));
    await first;

    expect(m.busy).toBe(false);
    expect(m.inputPwd.disabled).toBe(false);
    expect(m.btnSubmit.disabled).toBe(false);
    expect(m.errorEl.setText).toHaveBeenCalledWith("boom");

    await m.handleSubmit();
    expect(setupPin).toHaveBeenCalledTimes(2);
  });
});

describe("ChangeCredentialsModal — busy-флаг и запрет закрытия", () => {
  function makeModal(changeCredentials: jest.Mock) {
    const plugin = {
      settings: { email: "old@example.com" },
      changeCredentials,
    };
    const modal = new ChangeCredentialsModal({} as never, plugin as never);
    const m = modal as unknown as {
      inputOld: FakeInput;
      inputEmail: FakeInput;
      inputNew: FakeInput;
      inputConfirm: FakeInput;
      btnSubmit: { disabled: boolean };
      errorEl: ReturnType<typeof fakeErrorEl>;
      progressEl: { addClass: jest.Mock; removeClass: jest.Mock; querySelector: () => null };
      contentEl: { isConnected: boolean; empty: jest.Mock };
      busy: boolean;
      handleSubmit(): Promise<void>;
      close(): void;
    };
    m.inputOld = fakeInput("old-password");
    m.inputEmail = fakeInput("old@example.com");
    m.inputNew = fakeInput("new-password-123");
    m.inputConfirm = fakeInput("new-password-123");
    m.btnSubmit = { disabled: false };
    m.errorEl = fakeErrorEl();
    m.progressEl = { addClass: jest.fn(), removeClass: jest.fn(), querySelector: () => null };
    m.contentEl = { isConnected: true, empty: jest.fn() };
    return m;
  }

  test("повторный сабмит во время changeCredentials игнорируется", async () => {
    const d = deferred();
    const changeCredentials = jest.fn(() => d.promise);
    const m = makeModal(changeCredentials);

    const first = m.handleSubmit();
    expect(changeCredentials).toHaveBeenCalledTimes(1);
    expect(m.busy).toBe(true);
    expect(m.inputOld.disabled).toBe(true);

    await m.handleSubmit();
    expect(changeCredentials).toHaveBeenCalledTimes(1);

    d.resolve();
    await first;
    expect(m.busy).toBe(false);
  });

  test("close() заблокирован во время операции, разрешён после ошибки", async () => {
    const superClose = jest.spyOn(Modal.prototype, "close");
    const d = deferred();
    const changeCredentials = jest.fn(() => d.promise);
    const m = makeModal(changeCredentials);

    const first = m.handleSubmit();

    // Escape/крестик/клик по фону в Obsidian сводятся к close().
    m.close();
    expect(superClose).not.toHaveBeenCalled();
    // Пользователю показано объяснение.
    expect(m.errorEl.setText).toHaveBeenCalledWith(
      expect.stringContaining("дождитесь завершения")
    );

    d.reject(new Error("re-encrypt failed"));
    await first;

    // После ошибки закрытие снова разрешено.
    expect(m.busy).toBe(false);
    m.close();
    expect(superClose).toHaveBeenCalledTimes(1);
    superClose.mockRestore();
  });

  test("edge: ошибка при уже отсоединённом DOM не пишет в невидимый errorEl", async () => {
    const d = deferred();
    const changeCredentials = jest.fn(() => d.promise);
    const m = makeModal(changeCredentials);

    const first = m.handleSubmit();
    m.errorEl.setText.mockClear();
    m.contentEl.isConnected = false; // модал закрыт (например, выгрузка плагина)

    d.reject(new Error("late failure"));
    await first; // не должно бросить

    // Ошибка ушла в Notice, а не в отсоединённый DOM.
    expect(m.errorEl.setText).not.toHaveBeenCalled();
    expect(m.busy).toBe(false);
  });
});
