# Shadow Vault

**Transparent AES-256-GCM encryption for Obsidian.** Your vault files stay encrypted on disk at all times. Obsidian sees and works with plaintext — search, graph view, Dataview, all plugins work as usual. No workflow changes required.

> ✅ **Cross-platform** — works on desktop (Windows, macOS, Linux) and mobile (iOS, Android).

---

## Supported Platforms

- **Desktop** (v1.0.0+): Windows, macOS, Linux — uses Node.js `fs` and `crypto` modules, shadow vault on disk
- **Mobile** (v2.0.0+): iOS, Android — uses Web Crypto API, virtual shadow in memory

---

## How it works

Shadow Vault patches Obsidian's file adapter (`app.vault.adapter`) to transparently redirect all file operations:

### Desktop Architecture (v1.0.0)

```
On disk (original vault):          Obsidian sees (shadow vault):
  note.md.enc  ──decrypt──►  /tmp/.shadow-vault-xxxx/note.md
  photo.png.enc              /tmp/.shadow-vault-xxxx/photo.png
```

- **Original vault** — stores only `.enc` files (AES-256-GCM, binary)
- **Shadow vault** — sibling directory created at session start, deleted on lock
- **Write-through** — every save encrypts back to the original vault immediately and atomically
- **Lazy decryption** — files are decrypted on demand; opened notes get highest priority

### Mobile Architecture (v2.0.0)

```
On disk (vault):               Obsidian sees (virtual shadow):
  note.md.enc  ──decrypt──►  In-memory cache → note.md
  photo.png.enc              In-memory cache → photo.png
```

- **Original vault** — stores only `.enc` files (AES-256-GCM, binary)
- **Virtual shadow** — in-memory cache (Map<path, ArrayBuffer>), cleared on lock
- **Write-through** — every save encrypts back to `.enc` immediately
- **On-demand decryption** — files are decrypted when accessed, cached in memory

### Encryption format

```
[ IV (12 bytes) ][ Auth Tag (16 bytes) ][ Ciphertext ]
```

Key derivation: PBKDF2-SHA512, 310 000 iterations, 256-bit key. The PBKDF2 input is a fixed application-domain constant (`shadow-vault:v1`) — no per-vault salt is stored. This makes vaults recoverable from the password alone, with no `data.json` backup required.

---

## Features

- 🔐 **AES-256-GCM** — authenticated encryption, detects file tampering
- 🔄 **Transparent** — all Obsidian features work: search, graph, backlinks, Dataview
- ⚡ **Priority queue** — open a note instantly even while background decryption is running
- 🛡️ **Crash recovery** — detects unclean shutdown, re-encrypts unsaved changes on next start
- 🔑 **Password change** — re-encrypts all files with a new key (two-phase atomic operation)
- 💾 **Atomic writes** — temp file + rename, no partial writes on power loss
- 🚀 **Stream support** — large files (PDF, video) processed in chunks, never fully loaded into RAM

---

## Installation

### From Obsidian Community Plugins
1. Open **Settings → Community plugins → Browse**
2. Search for **Shadow Vault**
3. Install and enable

### Manual
1. Download `main.js`, `manifest.json`, `styles.css` from the [latest release](https://github.com/SolverNA/shadow-vault/releases/latest)
2. Copy to `<vault>/.obsidian/plugins/shadow-vault/`
3. Enable in **Settings → Community plugins**

---

## Usage

1. **First launch** — a modal appears asking you to create a password (min. 8 characters). All existing `.md` files in the vault are encrypted automatically.
2. **Every launch** — enter your password to unlock. Files decrypt in the background; a status bar counter shows progress.
3. **Lock** — use the command palette: `Shadow Vault: Lock vault`, or the button in Settings.
4. **Change password** — Settings → Shadow Vault → Dangerous zone → Change password. Requires the vault to be unlocked.

---

## Security notes

- The password cannot be recovered. There is no backdoor.
- The shadow vault is created **outside** the original vault directory (sibling folder), so it is never synced.
- The original vault can be safely synced via Git, Obsidian Sync, or cloud storage — only encrypted `.enc` files travel over the network.
- After a crash, Shadow Vault detects unsaved plaintext files in the shadow vault and re-encrypts them before starting a new session.

---

## Building from source

```bash
git clone https://github.com/SolverNA/shadow-vault
cd shadow-vault
npm install
npm run build   # produces main.js
npm test        # runs the test suite
```

---

## License

MIT — see [LICENSE](LICENSE)
