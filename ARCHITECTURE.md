# Shadow Vault — внутренняя архитектура

Техническое описание после переработки криптоядра (фазы 1–6).
Единое криптоядро, формат v2 с солью из email, миграция legacy → v2,
кроссплатформенность desktop + mobile.

---

## 1. Терминология

| Термин | Что означает |
|--------|--------------|
| **Оригинал** (`originalRoot`) | Реальная папка vault. Хранит **только** `.enc` + plaintext `.obsidian/`. |
| **Теневое хранилище** (`shadowRoot`) | Рабочая расшифрованная копия. **Desktop**: реальный каталог-сиблинг оригинала. **Mobile**: виртуальный in-memory кэш. Существует только в активной сессии. |
| **Сессия** | Период от ввода пароля до lock/закрытия Obsidian. |
| **Session-lock** | Маркер активной сессии для обнаружения краша при следующем старте. |
| **v2 / v2-chunked** | Текущий формат `.enc` (цельный `0x02` и чанковый `0x03`). |
| **legacy** | Старый формат без соли (домен `shadow-vault:v1`, без email). Мигрируется в v2. |

---

## 2. Модули

```
crypto/constants.ts      MAGIC, версии, IV/tag/key length, PBKDF2 (600k, SHA-512),
                         SALT_DOMAIN "shadow-vault:v2", параметры legacy.
crypto/platform.ts       isNodeRuntime(); ленивый nodeRequire() за рантайм-гейтом;
                         getSubtle() (WebCrypto на Node 16+ и в браузере); randomBytes().
crypto/key-derivation.ts deriveSalt(email)=SHA-256(normalize(email)‖domain);
                         deriveMasterKey(email,password)=PBKDF2 → 32 байта.
crypto/format.ts         writeContainer/parseContainer (v2);
                         writeChunkedHeader/writeSegment/parseChunkedContainer (v2-chunked);
                         detectFormat() → v2 | v2-chunked | legacy-node/web | unknown.
crypto/verification.ts   createVerificationBlob / verifyPassword (проверка до расшифровки).
crypto/legacy.ts         legacyDecrypt() trial-decrypt: node-layout, затем web-layout.
crypto/migration.ts      migrateBuffer() (legacy → v2 + round-trip verify),
                         probeLegacyPassword().
crypto/factory.ts        createCryptoEngine() → Node или Web по платформе.

crypto-engine.ts         NodeCryptoEngine: потоковое чтение/запись, чанковый формат
                         для больших файлов на desktop.
web-crypto-engine.ts     WebCryptoEngine: буферный AES-GCM для mobile/браузера.

shadow-vault-manager.ts  Desktop: реальный shadow, write-through, encryptLocks,
                         pendingWrites/drainPending, atomicWrite, миграция, export.
virtual-shadow-manager.ts Mobile: in-memory shadow, синхронный write-through, миграция.
adapter-patcher.ts       Mobile: патч read/write/list DataAdapter под виртуальный shadow.
platform-adapter.ts      Абстракция файловых операций (desktop fs / mobile vault adapter).
session-manager.ts       Crash recovery: mtime → semantic → integrity.
pin-store.ts             PIN-вход через key-wrapping (device-local localStorage).
auth-service.ts          Аутентификация: первый запуск / проверка пароля.
main.ts                  Точка входа, развод desktop/mobile, встройка миграции.
init-modal.ts / set-pin-modal.ts / settings-tab.ts  UI.
```

Кроссплатформенный инвариант: модули `crypto/*` (кроме внутренних node-хелперов
движка) и `pin-store.ts` **не импортируют node-модули на верхнем уровне**. Вся
криптография идёт через `getSubtle()`/`randomBytes()`, поэтому бандл грузится на
mobile без `ReferenceError`. Node-доступ — только за гейтом `isNodeRuntime()`.

---

## 3. Формат файлов

### v2 (цельный, `0x02`)

```
[ MAGIC "SVLT" (4) ][ version 0x02 (1) ][ IV (12) ][ ciphertext‖GCM-tag (16 в конце) ]
```

WebCrypto AES-GCM сам возвращает `ciphertext‖tag`; в Node `ciphertext` и
`getAuthTag()` склеиваются в том же порядке — layout идентичен.

### v2-chunked (`0x03`, файлы > 4 МБ на desktop)

```
[ MAGIC "SVLT" (4) ][ version 0x03 (1) ][ blockSize u32 LE (4) ]
затем сегменты: [ segLen u32 LE (4) ][ IV (12) ][ ciphertext‖tag (16) ]
```

Каждый сегмент — независимый AES-GCM (свой IV/tag), шифрует `blockSize` байт
plaintext (последний — остаток). Размер блока по умолчанию — 4 МБ. Читать v2-chunked
обязаны **обе** платформы; писать чанково умеет пока только desktop (на mobile файл
буферизуется и пишется цельным v2 либо читается посегментно в память).

### Деривация ключа

```
salt      = SHA-256( utf8(normalize(email)) ‖ utf8("shadow-vault:v2") )   → 32 байта
masterKey = PBKDF2( password, salt, 600 000, SHA-512 )                    → 32 байта
```

`verificationBlob` (в `data.json`) — `VERIFICATION_PLAINTEXT`, зашифрованный в v2.
Проверка пароля = расшифровать блоб и сравнить с константой, **до** касания реальных
файлов. В `data.json` также хранятся `email` (не секрет), `kdfIterations`,
`formatVersion`. Соль не хранится — выводится из email при каждом входе.

---

## 4. Потоки данных

### 4.1 Вход и разблокировка

1. `main.onload()` определяет платформу (`Platform.isDesktopApp`) и грузит настройки.
2. Пользователь вводит email (только первый запуск) + пароль, либо PIN.
   - **Пароль**: `AuthService.authenticate()` деривирует ключ и проверяет
     `verificationBlob`. Первый запуск — создаёт блоб и сохраняет настройки.
   - **PIN**: `PinStore.unlockWithPin()` разворачивает `wrappedMaster` → сырой
     masterKey, который загружается в движок напрямую (`loadRawKey`).
3. **Миграция legacy → v2**, если нужна (см. §5).
4. **Desktop**: `ShadowVaultManager` создаёт/восстанавливает реальный shadow,
   расшифровывает `.enc` → shadow, подменяет `adapter.basePath` на shadow,
   связывает `.obsidian`, ставит session-lock, включает write-through watcher.
   **Mobile**: `VirtualShadowManager` + `AdapterPatcher` патчат `DataAdapter`;
   расшифровка ленивая в in-memory кэш.

### 4.2 Расшифровка / чтение

- **Desktop**: Obsidian читает нативно из shadow (файлы уже расшифрованы).
- **Mobile**: `read`/`readBinary` идут через патч → `VirtualShadowManager`
  расшифровывает `.enc` (или берёт из кэша) → возвращает plaintext.

### 4.3 Write-through (запись)

- **Desktop**: после нативной записи в shadow плагин шифрует содержимое и
  **атомарно** (`atomicWrite`: tmp + `rename`) сохраняет в `originalRoot/<path>.enc`.
  Параллельные записи одного файла сериализуются per-file мьютексом `encryptLocks`.
  Каждый write-through регистрируется в `pendingWrites` для дренажа при закрытии.
  Большие файлы пишутся чанково (v2-chunked) потоково.
- **Mobile**: `write`/`writeBinary` через патч → `VirtualShadowManager` кладёт в кэш
  и **синхронно** шифрует в `.enc`.

### 4.4 Закрытие сессии (lock / выгрузка)

1. `drainPending()` — дождаться завершения активных write-through (`pendingWrites`
   + `encryptLocks`), с лимитом проходов.
2. **Desktop**: размонтировать shadow (`basePath` ← оригинал), доэшифровать
   изменённые файлы. Если остались несохранённые правки — **shadow НЕ удаляется**,
   остаётся для crash recovery.
3. Снять session-lock, обнулить ключ в RAM (`engine.destroy()`).

### 4.5 Отключение шифрования (disableEncryption)

Безопасный двухфазный экспорт:
1. `exportShadowToOriginal()` — расшифровать все файлы в оригинал и проверить
   (round-trip verify каждого). Список `exported` / `failed`.
2. Только после успешного экспорта — батч-удаление `.enc`, очистка адаптера,
   завершение сессии. При ошибках экспорта `.enc` не удаляются.

---

## 5. Миграция legacy → v2

Старые хранилища (формат без соли, домен `shadow-vault:v1`, без email) мигрируют
автоматически при первом входе после обновления. Встроено в поток входа в `main.ts`
(`migrateLegacyIfNeeded` на desktop, `migrateLegacyMobileIfNeeded` на mobile).

Два legacy-варианта по содержимому буфера **не различимы** надёжно:

```
legacy-node: [ IV(12) ][ AuthTag(16) ][ ciphertext ]   PBKDF2 310 000, SHA-512
legacy-web:  [ IV(12) ][ ciphertext‖tag(16 в конце) ]   PBKDF2 600 000, SHA-512
```

Поэтому применяется **trial-decrypt** (`legacyDecrypt`): сначала node-layout/params,
при провале GCM-аутентификации — web-layout. Распознанный вариант возвращается как
hint для ускорения bulk-миграции.

Контракт безопасности (`migrateBuffer`):
1. Уже мигрированный файл (v2 по MAGIC) пропускается → **идемпотентность**.
2. legacy расшифровывается trial-decrypt'ом.
3. Перешифровка новым v2-ключом (email+password).
4. **Обязательный round-trip verify**: новый v2-буфер расшифровывается обратно и
   побайтно сравнивается с исходным plaintext **перед** атомарной заменой файла.
   Если verify не прошёл — бросаем, файл **не заменяется**.

`probeLegacyPassword()` проверяет пароль на одном образце `.enc`, когда
`verificationBlob` отсутствует (совсем старое хранилище без блоба).

---

## 6. Crash recovery (SessionManager)

При обнаружении незавершённой сессии (есть прошлый shadow + session-lock) для
каждого файла shadow выполняется проверка в три этапа:

- **Этап 0 — mtime**: если `shadow.mtime <= original.mtime + допуск` → файл не
  менялся, пропускаем.
- **Этап 1 — semantic** (`compareSemantic`): расшифровать оригинал и сравнить
  побайтно с shadow. Идентичны → пропускаем (несмотря на mtime).
- **Этап 2 — integrity** (`checkFileIntegrity`): проверить, что shadow-файл не
  битый — magic-bytes известных форматов и валидность UTF-8 для текста. Если
  целостен и отличается → принять shadow как источник истины и перешифровать в
  оригинал. Если битый → оставить оригинал.

Session-lock хранится в папке плагина; создаётся при mount, снимается при
корректном завершении.

---

## 7. Кроссплатформенность

- Платформа определяется через `Platform.isDesktopApp` (obsidian) с приоритетом
  над `isNodeRuntime()`.
- Desktop-only менеджеры (`ShadowVaultManager`, node-fs хелперы) импортируются
  **динамически** только в desktop-ветке `main.ts`.
- `crypto/*` и `pin-store.ts` свободны от node-импортов верхнего уровня —
  гарантия загрузки бандла на mobile.
- Формат файлов и деривация ключа идентичны → хранилище переносимо между desktop
  и mobile без перешифровки.

---

## 8. Известные ограничения

- **v2-chunked пишется только на desktop.** Mobile читает чанковые файлы, но при
  записи использует цельный v2 (буферизация в памяти) — для очень больших
  вложений это ограничение по RAM.
- **Биометрия — заглушка** (`PinStore.isBiometricSupported()` всегда `false`): в
  песочнице Obsidian нет доступного нативного API. Механизм key-wrapping готов к
  подключению, как только появится API.
- **Смена email меняет соль → меняет ключ.** Существующие `.enc` после смены email
  без перешифровки не читаются (email фиксируется при первом запуске).

---

## 9. Что не менять без миграции

- Параметры формата и KDF в `crypto/constants.ts` (`MAGIC`, версии, `SALT_DOMAIN`,
  `PBKDF2_ITERATIONS`, layout v2/v2-chunked) — от них зависят уже зашифрованные
  данные пользователей.
- Параметры legacy (`LEGACY_*`) — нужны для расшифровки старых хранилищ при
  миграции; сверены байт-в-байт со старым кодом.
- Структура `data.json` (`verificationBlob`, `email`, `kdfIterations`,
  `formatVersion`).

Любое изменение здесь требует отдельного major-bump и migration-helper.
