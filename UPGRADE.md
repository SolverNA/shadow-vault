# Миграция на кросс-платформенность

## Текущее состояние

Плагин работает **только на десктопе** (Windows, macOS, Linux) из-за использования Node.js модулей:
- `fs` / `fs/promises` — прямой доступ к файловой системе
- `crypto` — Node.js криптография (AES-GCM, PBKDF2)
- `os` — определение количества CPU для параллелизма
- `path` — работа с путями файловой системы

**Архитектура:**
- Оригинальное хранилище: `.enc` файлы на диске
- Теневое хранилище: сиблинг-директория рядом с vault, расшифрованные файлы
- Obsidian монтирует shadow как `basePath`, работает с ним нативно
- Write-through шифрование: каждое изменение → немедленно в `.enc`

## Проблемы на мобильных платформах

### 1. Node.js модули недоступны
Мобильный Obsidian (iOS/Android) работает в WebView/JavaScriptCore — нет Node.js runtime.
- `import * as fs from "fs"` → **ReferenceError**
- `import * as crypto from "crypto"` → **ReferenceError**

### 2. Нет прямого доступа к файловой системе
Мобильный адаптер использует виртуальную FS (IndexedDB или platform-specific storage).
- Нет концепции "абсолютного пути"
- Нельзя создать "сиблинг-директорию" рядом с vault
- `adapter.getBasePath()` может вернуть виртуальный путь или `null`

### 3. Stream API отсутствует
- `fs.createReadStream()` / `fs.createWriteStream()` недоступны
- Большие файлы (>4MB) нужно обрабатывать chunk-based через `ArrayBuffer`

### 4. Symlinks не поддерживаются
- `.obsidian` symlink → original не работает на мобильных
- Конфигурация должна храниться иначе

---

## План миграции

### Этап 1: Подготовка — версионирование и ветвление

**Цель:** Сохранить текущую стабильную десктопную версию, начать разработку кросс-платформенной в отдельной ветке.

```bash
# 1. Создать тег для текущей десктопной версии
git tag v1.0.0-desktop -m "Stable desktop-only version"
git push origin v1.0.0-desktop

# 2. Создать ветку для кросс-платформенной разработки
git checkout -b feature/cross-platform
git push -u origin feature/cross-platform
```

**Структура веток:**
- `main` — стабильная десктопная версия (Node.js)
- `feature/cross-platform` — разработка кросс-платформенной версии (Web APIs)
- После завершения миграции: `feature/cross-platform` → `main` (major version bump: v2.0.0)

---

### Этап 2: Замена криптографии — Web Crypto API

**Файл:** `src/web-crypto-engine.ts` (новый)

**Задачи:**
1. Заменить `crypto.pbkdf2()` на `window.crypto.subtle.deriveBits()`
2. Заменить `crypto.createCipheriv()` на `window.crypto.subtle.encrypt()`
3. Заменить `crypto.createDecipheriv()` на `window.crypto.subtle.decrypt()`
4. Убрать stream-шифрование, реализовать chunk-based для больших файлов

**Пример:**
```typescript
export class WebCryptoEngine {
  private key: CryptoKey | null = null;

  async deriveKey(password: string): Promise<void> {
    const encoder = new TextEncoder();
    const passwordBuf = encoder.encode(password);
    const domainBuf = encoder.encode("shadow-vault:v1");

    // Import password as key material
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      passwordBuf,
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    // Derive 256-bit key
    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: domainBuf,
        iterations: 600_000,
        hash: "SHA-512",
      },
      keyMaterial,
      256
    );

    // Import as AES-GCM key
    this.key = await window.crypto.subtle.importKey(
      "raw",
      derivedBits,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async encryptBuffer(plaintext: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.key) throw new Error("Key not derived");

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      this.key,
      plaintext
    );

    // Format: IV (12 bytes) + ciphertext (includes auth tag)
    const result = new Uint8Array(12 + ciphertext.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertext), 12);
    return result.buffer;
  }

  async decryptBuffer(encrypted: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.key) throw new Error("Key not derived");

    const view = new Uint8Array(encrypted);
    const iv = view.slice(0, 12);
    const ciphertext = view.slice(12);

    return await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      this.key,
      ciphertext
    );
  }

  destroy(): void {
    this.key = null;
  }
}
```

**Коммит:**
```bash
git add src/web-crypto-engine.ts
git commit -m "feat: Web Crypto API engine для кросс-платформенности"
```

---

### Этап 3: Убрать зависимость от прямого fs

**Проблема:** `ShadowVaultManager` использует `fs.readFile`, `fs.writeFile`, `fs.mkdir` напрямую.

**Решение:** Обернуть все операции через абстракцию, которая на десктопе использует `fs`, на мобильных — `vault.adapter`.

**Файл:** `src/platform-adapter.ts` (новый)

```typescript
export interface PlatformAdapter {
  readBinary(path: string): Promise<ArrayBuffer>;
  writeBinary(path: string, data: ArrayBuffer): Promise<void>;
  exists(path: string): Promise<boolean>;
  remove(path: string): Promise<void>;
  list(path: string): Promise<{ files: string[]; folders: string[] }>;
  mkdir(path: string): Promise<void>;
}

// Десктопная реализация (Node.js fs)
export class DesktopAdapter implements PlatformAdapter {
  constructor(private basePath: string) {}

  async readBinary(path: string): Promise<ArrayBuffer> {
    const buf = await fsp.readFile(nodePath.join(this.basePath, path));
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }

  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    await fsp.writeFile(nodePath.join(this.basePath, path), Buffer.from(data));
  }

  // ... остальные методы
}

// Мобильная реализация (Obsidian Vault API)
export class MobileAdapter implements PlatformAdapter {
  constructor(private vault: Vault) {}

  async readBinary(path: string): Promise<ArrayBuffer> {
    return await this.vault.adapter.readBinary(path);
  }

  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    await this.vault.adapter.writeBinary(path, data);
  }

  // ... остальные методы
}
```

**Коммит:**
```bash
git add src/platform-adapter.ts
git commit -m "feat: абстракция файловой системы для кросс-платформенности"
```

---

### Этап 4: Переработка архитектуры — убрать shadow vault

**Проблема:** Концепция "теневого хранилища" (отдельная директория на диске) не работает на мобильных.

**Новая архитектура:**

#### Вариант A: In-memory shadow (простой, но требует RAM)
- Расшифрованные файлы хранятся в `Map<string, ArrayBuffer>` в памяти
- При `read()` — расшифровываем `.enc` → кэш → возвращаем
- При `write()` — сохраняем в кэш + немедленно шифруем в `.enc`
- При `lockVault()` — очищаем кэш

**Плюсы:** Работает везде, не требует дополнительного хранилища  
**Минусы:** Большие vault'ы могут не влезть в RAM мобильного устройства

#### Вариант B: Виртуальный shadow через IndexedDB (сложнее, но масштабируемо)
- Создаём отдельную IndexedDB базу для расшифрованных файлов
- При `read()` — проверяем IndexedDB → если нет, расшифровываем `.enc` → кэшируем
- При `write()` — сохраняем в IndexedDB + шифруем в `.enc`
- При `lockVault()` — удаляем IndexedDB базу

**Плюсы:** Масштабируется на большие vault'ы  
**Минусы:** Сложнее реализация, нужно управлять IndexedDB

**Рекомендация:** Начать с варианта A (in-memory), если пользователи жалуются на RAM — добавить вариант B.

**Файл:** `src/virtual-shadow-manager.ts` (новый)

```typescript
export class VirtualShadowManager {
  private cache: Map<string, ArrayBuffer> = new Map();
  private engine: WebCryptoEngine;

  constructor(
    engine: WebCryptoEngine,
    private adapter: PlatformAdapter
  ) {
    this.engine = engine;
  }

  async read(normalizedPath: string): Promise<ArrayBuffer> {
    // 1. Проверяем кэш
    if (this.cache.has(normalizedPath)) {
      return this.cache.get(normalizedPath)!;
    }

    // 2. Читаем .enc из хранилища
    const encPath = normalizedPath + ".enc";
    const encrypted = await this.adapter.readBinary(encPath);

    // 3. Расшифровываем
    const decrypted = await this.engine.decryptBuffer(encrypted);

    // 4. Кэшируем
    this.cache.set(normalizedPath, decrypted);

    return decrypted;
  }

  async write(normalizedPath: string, data: ArrayBuffer): Promise<void> {
    // 1. Сохраняем в кэш
    this.cache.set(normalizedPath, data);

    // 2. Шифруем
    const encrypted = await this.engine.encryptBuffer(data);

    // 3. Пишем .enc в хранилище
    const encPath = normalizedPath + ".enc";
    await this.adapter.writeBinary(encPath, encrypted);
  }

  clearCache(): void {
    this.cache.clear();
  }
}
```

**Коммит:**
```bash
git add src/virtual-shadow-manager.ts
git commit -m "feat: виртуальный shadow manager без файловой системы"
```

---

### Этап 5: Переписать monkey-patching адаптера

**Проблема:** Текущий код патчит `adapter.read()`, `adapter.write()` и подменяет `basePath`. На мобильных `basePath` может быть виртуальным или отсутствовать.

**Решение:** Патчить методы адаптера, но не трогать `basePath`. Вместо этого:
- `read()` → расшифровываем через `VirtualShadowManager`
- `write()` → шифруем через `VirtualShadowManager`
- `list()` → транслируем `.enc` → обычные имена (как сейчас)

**Файл:** `src/adapter-patcher.ts` (новый)

```typescript
export class AdapterPatcher {
  private originalMethods: Partial<IDataAdapter> = {};
  private patched = false;

  constructor(
    private shadowManager: VirtualShadowManager,
    private configDir: string
  ) {}

  patch(adapter: IDataAdapter): void {
    if (this.patched) return;

    this.originalMethods.read = adapter.read.bind(adapter);
    this.originalMethods.readBinary = adapter.readBinary.bind(adapter);
    this.originalMethods.write = adapter.write.bind(adapter);
    this.originalMethods.writeBinary = adapter.writeBinary.bind(adapter);
    // ... остальные методы

    adapter.read = (p) => this.patchedRead(p);
    adapter.readBinary = (p) => this.patchedReadBinary(p);
    adapter.write = (p, d, o) => this.patchedWrite(p, d, o);
    adapter.writeBinary = (p, d, o) => this.patchedWriteBinary(p, d, o);
    // ... остальные методы

    this.patched = true;
  }

  private async patchedRead(normalizedPath: string): Promise<string> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.read!(normalizedPath);
    }

    const buf = await this.shadowManager.read(normalizedPath);
    const decoder = new TextDecoder();
    return decoder.decode(buf);
  }

  private async patchedReadBinary(normalizedPath: string): Promise<ArrayBuffer> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.readBinary!(normalizedPath);
    }

    return await this.shadowManager.read(normalizedPath);
  }

  private async patchedWrite(
    normalizedPath: string,
    data: string,
    options?: DataWriteOptions
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.write!(normalizedPath, data, options);
    }

    const encoder = new TextEncoder();
    const buf = encoder.encode(data);
    await this.shadowManager.write(normalizedPath, buf.buffer);
  }

  private async patchedWriteBinary(
    normalizedPath: string,
    data: ArrayBuffer,
    options?: DataWriteOptions
  ): Promise<void> {
    if (this.isBypassPath(normalizedPath)) {
      return this.originalMethods.writeBinary!(normalizedPath, data, options);
    }

    await this.shadowManager.write(normalizedPath, data);
  }

  private isBypassPath(normalizedPath: string): boolean {
    return (
      normalizedPath === "" ||
      normalizedPath === this.configDir ||
      normalizedPath.startsWith(this.configDir + "/")
    );
  }

  unpatch(adapter: IDataAdapter): void {
    if (!this.patched) return;

    if (this.originalMethods.read) adapter.read = this.originalMethods.read;
    if (this.originalMethods.readBinary) adapter.readBinary = this.originalMethods.readBinary;
    if (this.originalMethods.write) adapter.write = this.originalMethods.write;
    if (this.originalMethods.writeBinary) adapter.writeBinary = this.originalMethods.writeBinary;
    // ... остальные методы

    this.originalMethods = {};
    this.patched = false;
  }
}
```

**Коммит:**
```bash
git add src/adapter-patcher.ts
git commit -m "feat: кросс-платформенный патчинг адаптера без basePath"
```

---

### Этап 6: Обновить main.ts — детекция платформы

**Файл:** `src/main.ts`

```typescript
import { Platform } from "obsidian";

async onload(): Promise<void> {
  await this.loadSettings();

  // Детекция платформы
  const isDesktop = Platform.isDesktopApp;
  const isMobile = Platform.isMobileApp;

  console.info(`[ShadowVault] Platform: desktop=${isDesktop}, mobile=${isMobile}`);

  // Выбор реализации
  if (isDesktop) {
    // Используем старую Node.js реализацию (для обратной совместимости)
    this.engine = new CryptoEngine();
    this.platformAdapter = new DesktopAdapter(this.getVaultBasePath()!);
  } else {
    // Используем новую Web Crypto реализацию
    this.engine = new WebCryptoEngine();
    this.platformAdapter = new MobileAdapter(this.app.vault);
  }

  // Остальная инициализация...
}
```

**Коммит:**
```bash
git add src/main.ts
git commit -m "feat: детекция платформы и выбор реализации"
```

---

### Этап 7: Убрать зависимости от Node.js модулей

**Задачи:**
1. Заменить все `import * as fs from "fs"` на `PlatformAdapter`
2. Заменить все `import * as nodePath from "path"` на `normalizePath()` из Obsidian API
3. Заменить `import * as os from "os"` на `navigator.hardwareConcurrency`
4. Убрать `SessionManager.session.lock` файл — использовать IndexedDB флаг

**Файлы для изменения:**
- `src/shadow-vault-manager.ts` → `src/virtual-shadow-manager.ts`
- `src/session-manager.ts` → убрать `fs.writeFileSync(lockPath)`
- `src/fs-utils.ts` → переписать на `PlatformAdapter`

**Коммиты:**
```bash
git add src/
git commit -m "refactor: убрать зависимости от Node.js fs"
git commit -m "refactor: убрать зависимости от Node.js path"
git commit -m "refactor: убрать зависимости от Node.js os"
```

---

### Этап 8: Обновить manifest.json

**Файл:** `manifest.json`

```json
{
  "id": "shadow-vault",
  "name": "Shadow Vault",
  "version": "2.0.0",
  "minAppVersion": "1.0.0",
  "description": "Прозрачное шифрование хранилища Obsidian (кросс-платформенное)",
  "author": "you-encrypt",
  "authorUrl": "https://github.com/SolverNA/shadow-vault",
  "isDesktopOnly": false
}
```

**Изменения:**
- `version`: `1.0.0` → `2.0.0` (major bump из-за архитектурных изменений)
- `isDesktopOnly`: `true` → `false` (теперь работает на мобильных)

**Коммит:**
```bash
git add manifest.json
git commit -m "chore: bump version to 2.0.0, enable mobile support"
```

---

### Этап 9: Тестирование

#### Десктоп (Windows/macOS/Linux)
```bash
# 1. Собрать плагин
npm run build

# 2. Скопировать в тестовое хранилище
cp main.js manifest.json styles.css ~/.obsidian/plugins/shadow-vault/

# 3. Перезапустить Obsidian, проверить:
# - Создание нового хранилища
# - Разблокировка существующего
# - Создание/редактирование/удаление файлов
# - Смена пароля
# - Отключение шифрования
```

#### Мобильные (iOS/Android)
```bash
# 1. Установить Obsidian на мобильное устройство
# 2. Включить "Developer mode" в настройках Obsidian
# 3. Скопировать плагин через iTunes (iOS) или ADB (Android)
# 4. Проверить те же сценарии что и на десктопе
```

**Коммит:**
```bash
git add tests/
git commit -m "test: добавить тесты для мобильных платформ"
```

---

### Этап 10: Документация

**Файлы для обновления:**
- `README.md` — добавить раздел "Поддерживаемые платформы"
- `CHANGELOG.md` — описать breaking changes в v2.0.0
- `docs/ARCHITECTURE.md` — обновить диаграммы архитектуры

**Коммит:**
```bash
git add README.md CHANGELOG.md docs/
git commit -m "docs: обновить документацию для v2.0.0"
```

---

### Этап 11: Merge в main

```bash
# 1. Убедиться что все тесты проходят
npm test

# 2. Создать PR
git push origin feature/cross-platform
# Открыть PR на GitHub: feature/cross-platform → main

# 3. После ревью — merge
git checkout main
git merge feature/cross-platform
git push origin main

# 4. Создать релиз
git tag v2.0.0 -m "Cross-platform support (desktop + mobile)"
git push origin v2.0.0
```

---

## Версионирование

### Семантическое версионирование (SemVer)

**Формат:** `MAJOR.MINOR.PATCH`

- **MAJOR** — несовместимые изменения API (breaking changes)
- **MINOR** — новая функциональность, обратно совместимая
- **PATCH** — исправления багов, обратно совместимые

### История версий

| Версия | Дата | Описание |
|--------|------|----------|
| `v1.0.0-desktop` | 2026-05-09 | Стабильная десктопная версия (Node.js) |
| `v2.0.0` | TBD | Кросс-платформенная версия (Web APIs) |

### Ветки

- `main` — стабильная версия для production
- `feature/cross-platform` — разработка кросс-платформенной версии
- `hotfix/*` — срочные исправления для production
- `release/*` — подготовка релизов

### Теги

- `v1.0.0-desktop` — последняя десктопная версия (Node.js)
- `v2.0.0` — первая кросс-платформенная версия (Web APIs)
- `v2.1.0` — добавление новых фич в кросс-платформенную версию
- `v2.0.1` — исправление багов в кросс-платформенной версии

---

## Риски и митигация

### Риск 1: Производительность на мобильных
**Проблема:** Web Crypto API медленнее чем Node.js crypto на больших файлах.  
**Митигация:** Chunk-based шифрование с прогресс-баром, оптимизация размера chunks.

### Риск 2: RAM на мобильных
**Проблема:** In-memory shadow может не влезть в RAM на больших vault'ах.  
**Митигация:** Реализовать LRU-кэш с лимитом памяти, добавить IndexedDB fallback.

### Риск 3: Совместимость с существующими vault'ами
**Проблема:** Пользователи с v1.0.0-desktop могут потерять данные при обновлении.  
**Митигация:** Автоматическая миграция при первом запуске v2.0.0, резервное копирование.

### Риск 4: Отладка на мобильных
**Проблема:** Сложнее дебажить на реальных устройствах.  
**Митигация:** Подробное логирование, remote debugging через Chrome DevTools (Android) / Safari Web Inspector (iOS).

---

## Чеклист перед релизом v2.0.0

- [ ] Все Node.js модули заменены на Web APIs
- [ ] Плагин собирается без ошибок (`npm run build`)
- [ ] Все тесты проходят (`npm test`)
- [ ] Протестировано на десктопе (Windows/macOS/Linux)
- [ ] Протестировано на мобильных (iOS/Android)
- [ ] Документация обновлена
- [ ] CHANGELOG.md содержит описание breaking changes
- [ ] manifest.json: `isDesktopOnly: false`
- [ ] Создан тег `v2.0.0`
- [ ] Релиз опубликован на GitHub

---

## Контакты и поддержка

- **GitHub:** https://github.com/SolverNA/shadow-vault
- **Issues:** https://github.com/SolverNA/shadow-vault/issues
- **Discussions:** https://github.com/SolverNA/shadow-vault/discussions
