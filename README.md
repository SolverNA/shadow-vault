# Shadow Vault

**Прозрачное шифрование хранилища Obsidian (AES-256-GCM).** Файлы на диске всегда зашифрованы (`.enc`). Obsidian при этом работает с расшифрованными файлами как обычно — поиск, граф, Dataview, любые плагины, рендер вложений. Менять привычный рабочий процесс не нужно.

> ✅ **Кроссплатформенность** — Desktop (Windows, macOS, Linux) и Mobile (iOS, Android).

---

## Идея и назначение

Оригинал хранилища на диске зашифрован **всегда**. Расшифрованные данные существуют только во время активной сессии (после ввода пароля) и только локально. То, что уходит в синхронизацию (Git, Obsidian Sync, облако), — это исключительно зашифрованные `.enc`-файлы.

Ключ к достижению «прозрачности» — **теневое хранилище** (shadow vault): расшифрованный клон, с которым Obsidian работает нативно, и **write-through** — каждое сохранение моментально шифруется обратно в оригинал.

---

## Как это работает

### Desktop

```
На диске (оригинал):              Obsidian видит (теневое хранилище):
  note.md.enc   ──decrypt──►   <shadowRoot>/note.md
  photo.png.enc                <shadowRoot>/photo.png
```

- **Оригинал** хранит только `.enc` (бинарный AES-256-GCM).
- **Теневое хранилище** — реальный каталог-сиблинг рядом с оригиналом, создаётся при разблокировке. Его путь подменяется как `basePath` адаптера Obsidian, после чего Obsidian считает shadow своим хранилищем целиком (нативный fs, `getResourcePath()`, рендер картинок/PDF, вложения — всё работает без костылей).
- **Write-through**: каждое `write/writeBinary` в shadow синхронно шифруется и атомарно (запись во временный файл + `rename`) сохраняется в `originalRoot/<path>.enc`. Параллельные записи в один файл сериализуются per-file мьютексом.

### Mobile

```
На диске (оригинал):              Obsidian видит (виртуальный shadow):
  note.md.enc   ──decrypt──►   in-memory кэш → note.md
  photo.png.enc                in-memory кэш → photo.png
```

На мобильных нет Node-`fs`, поэтому реальный каталог-клон создать нельзя. Вместо него — **виртуальное теневое хранилище в памяти** (`VirtualShadowManager`) и **пропатченный `DataAdapter`** (`AdapterPatcher`): `read`/`write` перенаправляются в кэш, `list` транслирует `.enc` → обычные имена. Write-through синхронный: запись сразу шифруется в `.enc`.

Криптография на обеих платформах **байт-в-байт одинакова**, поэтому хранилище переносимо между desktop и mobile без перешифровки.

---

## Безопасность

### Формат файла v2

```
[ MAGIC "SVLT" (4) ][ version 0x02 (1) ][ IV (12) ][ ciphertext‖GCM-tag (16 в конце) ]
```

Для больших файлов (> 4 МБ) на desktop используется чанковый под-формат **v2-chunked** (version `0x03`): последовательность независимых AES-GCM-сегментов (у каждого свой IV и tag) с заголовком, где указан размер блока. Это даёт потоковую обработку тяжёлых вложений без загрузки всего файла в RAM. Читать v2-chunked умеют **обе** платформы; писать чанково — пока только desktop.

### Деривация ключа

```
salt      = SHA-256( normalize(email) ‖ "shadow-vault:v2" )       → 32 байта
masterKey = PBKDF2( password, salt, 600 000, SHA-512 )            → 32 байта (AES-256)
```

- `normalize(email)` = `trim().toLowerCase()`.
- Деривация идёт через WebCrypto SubtleCrypto, доступный и в браузере, и в Node 16+ — отсюда идентичность ключа на всех платформах.
- **Вход = email + password.** Email не секрет, хранится в `data.json`, чтобы подставляться автоматически (пользователь вводит только пароль). Правильность пароля проверяется через verification blob **до** расшифровки реальных файлов.

### Быстрый вход по PIN (опционально)

PIN не деривирует мастер-ключ напрямую, а **оборачивает** его (key-wrapping):

```
pinKey        = PBKDF2( pin, deviceSalt, SHA-512 )
wrappedMaster = AES-GCM( masterKey, pinKey )
```

- `wrappedMaster`, `deviceSalt` и счётчик попыток хранятся **только локально** (`window.localStorage`) и **никогда не синхронизируются** — это не файл хранилища и не `data.json`.
- Лимит — 5 неверных попыток, после чего PIN-данные стираются и требуется полный пароль.
- Пароль остаётся корнем доверия: PIN — лишь локальное удобство, не замена пароля.

**Биометрия** — точка расширения на том же механизме key-wrapping, пока заглушка: в песочнице Obsidian нет доступного нативного API FaceID/Touch ID.

### Прочее

- AES-256-GCM — аутентифицированное шифрование: подмена/повреждение `.enc` обнаруживается.
- Пароль восстановить нельзя — бэкдора нет.
- Синхронизировать оригинал безопасно: по сети идут только `.enc`.

---

## Установка

### Из Community Plugins
1. **Settings → Community plugins → Browse**
2. Найти **Shadow Vault**
3. Установить и включить

### Вручную
1. Скачать `main.js`, `manifest.json`, `styles.css` из последнего релиза.
2. Скопировать в `<vault>/.obsidian/plugins/shadow-vault/`.
3. Включить в **Settings → Community plugins**.

---

## Использование

1. **Первый запуск** — модал просит ввести **email** и создать **пароль**. Существующие файлы хранилища шифруются автоматически.
2. **Каждый запуск** — ввод пароля (email подставляется из настроек) или быстрый вход по PIN, если он настроен.
3. **PIN** — настраивается в Settings → Shadow Vault; хранится только на этом устройстве.
4. **Блокировка** — команда `Shadow Vault: Lock vault` или кнопка в настройках.
5. **Смена пароля** — Settings → Shadow Vault → опасная зона. Перешифровывает хранилище новым ключом.
6. **Отключение шифрования** — безопасный экспорт: все файлы расшифровываются и проверяются (round-trip verify), и только потом `.enc` удаляются батчем.

> ⚠️ Перед обновлением со старой версии прочитайте **UPGRADE.md** — формат изменился, при первом входе будет автоматическая миграция.

---

## Кроссплатформенность

- Поддержка: Windows, macOS, Linux, Android, iOS.
- Node-модули (`crypto`/`fs`/`os`/`path`) грузятся **лениво за рантайм-гейтом** (`isNodeRuntime`), поэтому бандл загружается на mobile без падения. Desktop-only менеджеры импортируются динамически только в desktop-ветке.
- Криптоядро единое (WebCrypto SubtleCrypto), формат файлов идентичен — хранилище переносимо между платформами.

---

## Структура проекта (кратко)

```
src/
├── crypto/
│   ├── constants.ts       параметры формата и KDF (единые для всех платформ)
│   ├── platform.ts        isNodeRuntime, ленивый nodeRequire, getSubtle, randomBytes
│   ├── key-derivation.ts  deriveSalt / deriveMasterKey (email+password)
│   ├── format.ts          контейнеры v2 / v2-chunked, детектор формата
│   ├── verification.ts    verification blob (проверка пароля до расшифровки)
│   ├── legacy.ts          trial-decrypt старого формата (для миграции)
│   ├── migration.ts       legacy → v2 с round-trip verify
│   └── factory.ts         выбор движка по платформе
├── crypto-engine.ts       NodeCryptoEngine (desktop, потоковое чтение/запись)
├── web-crypto-engine.ts   WebCryptoEngine (mobile/браузер)
├── shadow-vault-manager.ts   реальное теневое хранилище + write-through (desktop)
├── virtual-shadow-manager.ts in-memory shadow (mobile)
├── adapter-patcher.ts     патч DataAdapter (mobile)
├── platform-adapter.ts    абстракция файловых операций
├── session-manager.ts     crash recovery (mtime + semantic + integrity)
├── pin-store.ts           PIN-вход через key-wrapping (device-local)
├── auth-service.ts        бизнес-логика аутентификации
├── main.ts                точка входа, развод desktop/mobile
├── init-modal.ts / set-pin-modal.ts / settings-tab.ts   UI
└── types.ts               PluginSettings и общие типы
```

---

## Сборка из исходников

```bash
git clone <repo> && cd shadow-vault
npm install
npm run build    # esbuild + tsc --noEmit → main.js
npm test         # jest (244 теста)
```

---

## License

MIT
