/**
 * Двухэтапная проверка целостности файла для Crash Recovery.
 *
 * Этап 1 (semantic): расшифровываем оригинальный .enc и сравниваем побайтово
 *   с shadow-копией. Идентичны → нет изменений. Различаются → переходим к Этапу 2.
 *
 * Этап 2 (file integrity): проверяем что shadow-файл не «битый»:
 *   - валидная UTF-8 для текстовых форматов (.md, .txt, .json, .canvas);
 *   - валидные magic bytes для известных бинарников (.png, .jpg, .pdf, .zip);
 *   - размер > 0 для непустых файлов;
 *   - отсутствие replacement-символов в текстовых данных (артефакт битой кодировки).
 *
 * Если shadow прошёл Этап 2 → можем доверять и шифровать обратно в оригинал.
 * Если не прошёл → оставляем оригинал без изменений, сообщаем пользователю.
 */

/**
 * Чистое расширение файла (без зависимости от node:path) — модуль mobile-safe.
 * Возвращает суффикс начиная с последней точки в имени, включая точку (".md").
 * Поведение совпадает с path.extname для типичных путей хранилища.
 */
function extname(p: string): string {
  const base = p.slice(p.replace(/\\/g, "/").lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return ""; // нет точки или dotfile без расширения
  return base.slice(dot);
}

/** Результат семантической сверки (Этап 1) */
export type SemanticDiff =
  | { kind: "equal" }
  | { kind: "different"; reason: string }
  | { kind: "original-missing" }
  | { kind: "original-corrupt"; error: string };

/** Результат файловой проверки целостности (Этап 2) */
export type IntegrityResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Этап 1: семантическое сравнение shadow-файла с расшифрованным оригиналом.
 * Принимает уже прочитанные буферы (вызывающий отвечает за расшифровку).
 *
 * @param shadowBuf  Буфер shadow-файла
 * @param originalDecryptedBuf  Расшифрованный буфер оригинала, либо null если оригинал отсутствует/повреждён
 */
export function compareSemantic(
  shadowBuf: Buffer,
  originalDecryptedBuf: Buffer | null
): SemanticDiff {
  if (originalDecryptedBuf === null) {
    return { kind: "original-missing" };
  }
  if (shadowBuf.length === originalDecryptedBuf.length && shadowBuf.equals(originalDecryptedBuf)) {
    return { kind: "equal" };
  }
  // Грубый размер изменений — для логирования
  const sizeDiff = Math.abs(shadowBuf.length - originalDecryptedBuf.length);
  return {
    kind: "different",
    reason: `размеры: shadow=${shadowBuf.length} б, original=${originalDecryptedBuf.length} б (Δ=${sizeDiff} б)`,
  };
}

/**
 * Этап 2: проверка целостности shadow-файла без сравнения с оригиналом.
 * Проверки:
 *   - размер > 0 (если ожидается не пустой файл) — простая sanity;
 *   - известные magic bytes для бинарных форматов (PNG, JPEG, PDF, ZIP, GIF);
 *   - валидная UTF-8 для текстовых форматов (без replacement char U+FFFD).
 */
export function checkFileIntegrity(
  normalizedPath: string,
  buf: Buffer
): IntegrityResult {
  const ext = extname(normalizedPath).toLowerCase();

  if (buf.length === 0) {
    // Пустой файл — допустимо для текстовых форматов и новых заметок
    return { ok: true };
  }

  // Бинарные форматы — проверяем magic bytes
  const binCheck = checkBinaryMagic(ext, buf);
  if (binCheck !== null) return binCheck;

  // Текстовые форматы — валидная UTF-8
  if (isTextExtension(ext)) {
    return checkUtf8Validity(buf);
  }

  // Неизвестный формат — пропускаем (нечем проверять)
  return { ok: true };
}

// ─────────────────────────────────────────────
// Внутренние хелперы
// ─────────────────────────────────────────────

const BINARY_SIGNATURES: Record<string, { magic: Buffer; format: string }[]> = {
  ".png":  [{ magic: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), format: "PNG" }],
  ".jpg":  [{ magic: Buffer.from([0xff, 0xd8, 0xff]), format: "JPEG" }],
  ".jpeg": [{ magic: Buffer.from([0xff, 0xd8, 0xff]), format: "JPEG" }],
  ".gif":  [
    { magic: Buffer.from("GIF87a", "ascii"), format: "GIF87a" },
    { magic: Buffer.from("GIF89a", "ascii"), format: "GIF89a" },
  ],
  ".pdf":  [{ magic: Buffer.from("%PDF-", "ascii"), format: "PDF" }],
  ".zip":  [{ magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]), format: "ZIP" }],
  ".docx": [{ magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]), format: "ZIP/DOCX" }],
  ".xlsx": [{ magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]), format: "ZIP/XLSX" }],
  ".pptx": [{ magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]), format: "ZIP/PPTX" }],
  ".webp": [{ magic: Buffer.from("RIFF", "ascii"), format: "RIFF/WebP" }],
  ".mp3":  [{ magic: Buffer.from([0x49, 0x44, 0x33]), format: "ID3/MP3" }],
  ".mp4":  [{ magic: Buffer.from("ftyp", "ascii"), format: "MP4" }], // встречается со смещением 4
};

function checkBinaryMagic(ext: string, buf: Buffer): IntegrityResult | null {
  const sigs = BINARY_SIGNATURES[ext];
  if (!sigs) return null;

  for (const sig of sigs) {
    // .mp4 имеет ftyp на смещении 4, остальные — с начала
    const offset = ext === ".mp4" ? 4 : 0;
    if (buf.length < offset + sig.magic.length) continue;
    const slice = buf.subarray(offset, offset + sig.magic.length);
    if (slice.equals(sig.magic)) {
      return { ok: true };
    }
  }
  return {
    ok: false,
    reason: `magic bytes не совпадают для ${ext} — файл повреждён или это не ${ext}`,
  };
}

const TEXT_EXTENSIONS = new Set([
  ".md",
  ".txt",
  ".json",
  ".canvas",
  ".csv",
  ".yaml",
  ".yml",
  ".html",
  ".htm",
  ".css",
  ".js",
  ".ts",
  ".xml",
  ".svg",
]);

function isTextExtension(ext: string): boolean {
  return TEXT_EXTENSIONS.has(ext);
}

function checkUtf8Validity(buf: Buffer): IntegrityResult {
  // TextDecoder с fatal=true бросит при невалидной UTF-8
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    const text = decoder.decode(buf);

    // Дополнительно: если есть U+FFFD (replacement char), значит TextDecoder
    // в нон-fatal режиме где-то проскочил — тут же при fatal=true это уже не нужно,
    // но оставим как страховку для случаев BOM/zero-width-нюансов.
    if (text.includes("�")) {
      return { ok: false, reason: "обнаружен Unicode replacement character (битая кодировка)" };
    }
    return { ok: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `невалидная UTF-8: ${msg}` };
  }
}
