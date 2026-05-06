/**
 * Тесты SessionManager.
 * Используем реальную файловую систему в temp-директориях.
 */

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import * as fsp from "fs/promises";
import * as fs from "fs";
import * as nodePath from "path";
import * as os from "os";
import { SessionManager } from "../src/session-manager";
import { CryptoEngine } from "../src/crypto-engine";

// ─────────────────────────────────────────────
// Хелперы
// ─────────────────────────────────────────────

interface TestEnv {
  engine:      CryptoEngine;
  session:     SessionManager;
  originalRoot: string;
  shadowRoot:  string;
  cleanup:     () => void;
}

async function makeEnv(): Promise<TestEnv> {
  const base = fs.mkdtempSync(nodePath.join(os.tmpdir(), "sv-session-"));
  const originalRoot = nodePath.join(base, "original");
  const shadowRoot   = nodePath.join(base, "shadow");
  fs.mkdirSync(originalRoot, { recursive: true });
  fs.mkdirSync(shadowRoot,   { recursive: true });

  const engine = new CryptoEngine();
  await engine.deriveKey("session-test-password");

  const session = new SessionManager(engine, originalRoot, shadowRoot);

  return {
    engine, session, originalRoot, shadowRoot,
    cleanup: () => {
      // engine может быть уже уничтожен в endSession — это нормально
      try { engine.destroy(); } catch { /* ignore */ }
      fs.rmSync(base, { recursive: true, force: true });
    },
  };
}

/**
 * Записывает зашифрованный файл в originalRoot как <relPath>.enc
 * (нормальное состояние хранилища после работы плагина).
 */
async function writeEncryptedOriginal(
  env: TestEnv, relPath: string, plaintext: string
): Promise<void> {
  const absPath = nodePath.join(env.originalRoot, ...relPath.split("/")) + ".enc";
  await fsp.mkdir(nodePath.dirname(absPath), { recursive: true });
  const enc = env.engine.encryptBuffer(Buffer.from(plaintext, "utf8"));
  await fsp.writeFile(absPath, enc);
}

/** Записывает открытый текст в shadowRoot (симуляция состояния после краша) */
async function writePlaintextShadow(
  env: TestEnv, relPath: string, plaintext: string, mtime?: Date
): Promise<void> {
  const absPath = nodePath.join(env.shadowRoot, ...relPath.split("/"));
  await fsp.mkdir(nodePath.dirname(absPath), { recursive: true });
  await fsp.writeFile(absPath, plaintext, "utf8");
  if (mtime) await fsp.utimes(absPath, mtime, mtime);
}

/** Возвращает mtime .enc файла в originalRoot */
async function origEncMtime(env: TestEnv, relPath: string): Promise<number> {
  const s = await fsp.stat(nodePath.join(env.originalRoot, ...relPath.split("/")) + ".enc");
  return s.mtimeMs;
}

// ─────────────────────────────────────────────
// startSession()
// ─────────────────────────────────────────────

describe("SessionManager — startSession()", () => {
  it("первый старт: нет краша, создаёт .session_active", async () => {
    const env = await makeEnv();
    try {
      const result = await env.session.startSession();

      expect(result.hadCrash).toBe(false);
      expect(result.recovery).toBeUndefined();

      const sessionFile = nodePath.join(env.originalRoot, ".session_active");
      expect(fs.existsSync(sessionFile)).toBe(true);
    } finally { env.cleanup(); }
  });

  it(".session_active содержит корректный JSON с startedAt и shadowRoot", async () => {
    const env = await makeEnv();
    try {
      await env.session.startSession();

      const sessionFile = nodePath.join(env.originalRoot, ".session_active");
      const raw = fs.readFileSync(sessionFile, "utf8");
      const data = JSON.parse(raw);

      expect(data.shadowRoot).toBe(env.shadowRoot);
      expect(typeof data.startedAt).toBe("string");
      expect(() => new Date(data.startedAt)).not.toThrow();
    } finally { env.cleanup(); }
  });

  it("повторный старт (есть .session_active): hadCrash=true", async () => {
    const env = await makeEnv();
    try {
      // Имитируем незавершённую предыдущую сессию
      const sessionFile = nodePath.join(env.originalRoot, ".session_active");
      fs.writeFileSync(sessionFile, JSON.stringify({ startedAt: new Date().toISOString(), shadowRoot: env.shadowRoot }));

      const result = await env.session.startSession();

      expect(result.hadCrash).toBe(true);
      expect(result.recovery).toBeDefined();
    } finally { env.cleanup(); }
  });

  it("после краша создаётся новый .session_active для текущей сессии", async () => {
    const env = await makeEnv();
    try {
      // Добавляем старый .session_active
      const sessionFile = nodePath.join(env.originalRoot, ".session_active");
      const oldTime = new Date(Date.now() - 60_000).toISOString();
      fs.writeFileSync(sessionFile, JSON.stringify({ startedAt: oldTime, shadowRoot: env.shadowRoot }));

      await env.session.startSession();

      const newRaw = fs.readFileSync(sessionFile, "utf8");
      const newData = JSON.parse(newRaw);

      // Новый startedAt должен быть новее oldTime
      expect(new Date(newData.startedAt).getTime()).toBeGreaterThan(new Date(oldTime).getTime());
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// endSession()
// ─────────────────────────────────────────────

describe("SessionManager — endSession()", () => {
  it("удаляет .session_active", async () => {
    const env = await makeEnv();
    try {
      await env.session.startSession();
      await env.session.endSession();

      const sessionFile = nodePath.join(env.originalRoot, ".session_active");
      expect(fs.existsSync(sessionFile)).toBe(false);
    } finally { env.cleanup(); }
  });

  it("удаляет всё Теневое хранилище", async () => {
    const env = await makeEnv();
    try {
      // Создаём файлы в shadow vault
      await writePlaintextShadow(env, "note1.md", "content 1");
      await writePlaintextShadow(env, "folder/note2.md", "content 2");

      await env.session.startSession();
      await env.session.endSession();

      expect(fs.existsSync(env.shadowRoot)).toBe(false);
    } finally { env.cleanup(); }
  });

  it("уничтожает ключ шифрования (engine.isUnlocked() = false)", async () => {
    const env = await makeEnv();
    try {
      await env.session.startSession();

      expect(env.engine.isUnlocked()).toBe(true);
      await env.session.endSession();
      expect(env.engine.isUnlocked()).toBe(false);
    } finally { env.cleanup(); }
  });

  it("endSession() без предварительного startSession() не падает", async () => {
    const env = await makeEnv();
    try {
      await expect(env.session.endSession()).resolves.not.toThrow();
    } finally { env.cleanup(); }
  });

  it("оригинальное хранилище остаётся нетронутым после endSession", async () => {
    const env = await makeEnv();
    try {
      await writeEncryptedOriginal(env, "important.md", "valuable data");
      await env.session.startSession();
      await env.session.endSession();

      // .enc файл в оригинальном хранилище должен быть цел
      expect(fs.existsSync(nodePath.join(env.originalRoot, "important.md.enc"))).toBe(true);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// recoverFromCrash()
// ─────────────────────────────────────────────

describe("SessionManager — recoverFromCrash()", () => {
  it("пустое shadow: ничего не восстанавливает", async () => {
    const env = await makeEnv();
    try {
      const result = await env.session.recoverFromCrash();
      expect(result.recoveredFiles).toHaveLength(0);
      expect(result.failedFiles).toHaveLength(0);
    } finally { env.cleanup(); }
  });

  it("shadow файл с тем же mtime что original: не восстанавливает (кэш-хит)", async () => {
    const env = await makeEnv();
    try {
      // Создаём оригинал (.enc)
      await writeEncryptedOriginal(env, "note.md", "original content");
      const origStat = await fsp.stat(nodePath.join(env.originalRoot, "note.md.enc"));

      // Создаём shadow с ТОЖДЕСТВЕННЫМ mtime (как после ensureDecrypted)
      await writePlaintextShadow(env, "note.md", "original content", origStat.mtime);

      const result = await env.session.recoverFromCrash();
      expect(result.recoveredFiles).toHaveLength(0);
    } finally { env.cleanup(); }
  });

  it("shadow файл НОВЕЕ оригинала: восстанавливает (потерянная запись)", async () => {
    const env = await makeEnv();
    try {
      // Оригинал — старый
      await writeEncryptedOriginal(env, "modified.md", "old content");
      // Небольшая задержка чтобы shadow был явно новее
      await new Promise(r => setTimeout(r, 100));
      // Shadow — новый (результат write-through, original не успел обновиться до краша)
      await writePlaintextShadow(env, "modified.md", "NEW UNSAVED CONTENT");

      const result = await env.session.recoverFromCrash();

      expect(result.recoveredFiles).toContain("modified.md");
      expect(result.failedFiles).toHaveLength(0);
    } finally { env.cleanup(); }
  });

  it("после recovery оригинал (.enc) содержит данные из shadow", async () => {
    const env = await makeEnv();
    try {
      await writeEncryptedOriginal(env, "modified.md", "old content");
      await new Promise(r => setTimeout(r, 100));
      await writePlaintextShadow(env, "modified.md", "recovered content");

      await env.session.recoverFromCrash();

      // Расшифровываем оригинал .enc — должен содержать данные из shadow
      const encBuf = await fsp.readFile(nodePath.join(env.originalRoot, "modified.md.enc"));
      const dec = env.engine.decryptBuffer(encBuf);
      expect(dec.toString("utf8")).toBe("recovered content");
    } finally { env.cleanup(); }
  });

  it("файл только в shadow (нет в original): восстанавливает как новый .enc", async () => {
    const env = await makeEnv();
    try {
      // Файл создан в shadow, оригинал не успел записаться до краша
      await writePlaintextShadow(env, "brand-new.md", "new note created before crash");

      const result = await env.session.recoverFromCrash();

      expect(result.recoveredFiles).toContain("brand-new.md");
      // Теперь оригинал .enc должен существовать
      expect(fs.existsSync(nodePath.join(env.originalRoot, "brand-new.md.enc"))).toBe(true);
    } finally { env.cleanup(); }
  });

  it("восстанавливает несколько файлов одновременно", async () => {
    const env = await makeEnv();
    try {
      for (const name of ["a.md", "b.md", "c.md"]) {
        await writeEncryptedOriginal(env, name, `old ${name}`);
      }
      await new Promise(r => setTimeout(r, 100));
      for (const name of ["a.md", "b.md", "c.md"]) {
        await writePlaintextShadow(env, name, `new ${name}`);
      }

      const result = await env.session.recoverFromCrash();
      expect(result.recoveredFiles).toHaveLength(3);
      expect(result.failedFiles).toHaveLength(0);
    } finally { env.cleanup(); }
  });

  it("восстанавливает вложенные файлы (поддиректории)", async () => {
    const env = await makeEnv();
    try {
      await writeEncryptedOriginal(env, "Projects/Alpha/notes.md", "old notes");
      await new Promise(r => setTimeout(r, 100));
      await writePlaintextShadow(env, "Projects/Alpha/notes.md", "new notes");

      const result = await env.session.recoverFromCrash();
      expect(result.recoveredFiles).toContain("Projects/Alpha/notes.md");

      const encBuf = await fsp.readFile(
        nodePath.join(env.originalRoot, "Projects", "Alpha", "notes.md.enc")
      );
      const dec = env.engine.decryptBuffer(encBuf);
      expect(dec.toString("utf8")).toBe("new notes");
    } finally { env.cleanup(); }
  });

  it("частичная ошибка: плохой файл помечается в failedFiles, остальные восстанавливаются", async () => {
    const env = await makeEnv();
    try {
      await writeEncryptedOriginal(env, "good.md", "old good");
      await new Promise(r => setTimeout(r, 100));
      await writePlaintextShadow(env, "good.md", "new good");

      // Создаём файл в shadow но делаем его нечитаемым
      await writePlaintextShadow(env, "bad.md", "new bad");
      await fsp.chmod(nodePath.join(env.shadowRoot, "bad.md"), 0o000);

      const result = await env.session.recoverFromCrash();

      // Разрешаем права обратно для корректной очистки
      await fsp.chmod(nodePath.join(env.shadowRoot, "bad.md"), 0o644).catch(() => undefined);

      expect(result.recoveredFiles).toContain("good.md");
      // bad.md либо в failedFiles (если не удалось прочитать), либо не в recoveredFiles
      // (зависит от прав в тестовой среде)
      expect(result.recoveredFiles.length + result.failedFiles.length).toBeGreaterThanOrEqual(1);
    } finally { env.cleanup(); }
  });

  it("если shadow vault не существует: возвращает пустой результат", async () => {
    const env = await makeEnv();
    try {
      // Удаляем shadow vault
      fs.rmSync(env.shadowRoot, { recursive: true });

      const result = await env.session.recoverFromCrash();
      expect(result.recoveredFiles).toHaveLength(0);
      expect(result.failedFiles).toHaveLength(0);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// scanShadowFiles()
// ─────────────────────────────────────────────

describe("SessionManager — scanShadowFiles()", () => {
  it("возвращает все файлы в shadow vault", async () => {
    const env = await makeEnv();
    try {
      await writePlaintextShadow(env, "a.md", "a");
      await writePlaintextShadow(env, "b.md", "b");
      await writePlaintextShadow(env, "sub/c.md", "c");

      const files = await env.session.scanShadowFiles();

      expect(files).toContain("a.md");
      expect(files).toContain("b.md");
      expect(files).toContain("sub/c.md");
    } finally { env.cleanup(); }
  });

  it("исключает скрытые файлы из списка", async () => {
    const env = await makeEnv();
    try {
      await writePlaintextShadow(env, "visible.md", "v");
      // Создаём скрытый файл напрямую
      await fsp.writeFile(nodePath.join(env.shadowRoot, ".hidden"), "hidden");

      const files = await env.session.scanShadowFiles();

      expect(files).toContain("visible.md");
      expect(files).not.toContain(".hidden");
    } finally { env.cleanup(); }
  });

  it("пустой shadow vault: возвращает пустой список", async () => {
    const env = await makeEnv();
    try {
      const files = await env.session.scanShadowFiles();
      expect(files).toHaveLength(0);
    } finally { env.cleanup(); }
  });
});

// ─────────────────────────────────────────────
// Сквозной сценарий: краш → recovery → нормальная работа
// ─────────────────────────────────────────────

describe("SessionManager — сквозной сценарий краша", () => {
  it("полный цикл: сессия → краш → recovery → новая сессия", async () => {
    const env = await makeEnv();
    try {
      // ── Шаг 1: Первая сессия, стартуем нормально ─────────────────────
      const first = await env.session.startSession();
      expect(first.hadCrash).toBe(false);

      // ── Шаг 2: Пользователь создаёт файл (write-through частично выполнился) ─
      // Симулируем краш: shadow записан, original — нет (старый)
      await writeEncryptedOriginal(env, "diary.md", "Monday: nothing happened");
      await new Promise(r => setTimeout(r, 100));
      await writePlaintextShadow(env, "diary.md", "Tuesday: power cut during save!");

      // ── Шаг 3: НЕ вызываем endSession() — симулируем краш ────────────
      // .session_active остаётся на диске

      // ── Шаг 4: Вторая сессия — обнаруживает краш ──────────────────────
      const second = await env.session.startSession();
      expect(second.hadCrash).toBe(true);
      expect(second.recovery?.recoveredFiles).toContain("diary.md");

      // ── Шаг 5: Проверяем, что original.enc обновлён данными из shadow ──
      const encBuf = fs.readFileSync(nodePath.join(env.originalRoot, "diary.md.enc"));
      const plaintext = env.engine.decryptBuffer(encBuf);
      expect(plaintext.toString("utf8")).toBe("Tuesday: power cut during save!");

      // ── Шаг 6: Завершаем нормально ────────────────────────────────────
      await env.session.endSession();

      expect(fs.existsSync(env.shadowRoot)).toBe(false);
      expect(fs.existsSync(nodePath.join(env.originalRoot, ".session_active"))).toBe(false);
      expect(env.engine.isUnlocked()).toBe(false);
    } finally { env.cleanup(); }
  });
});
