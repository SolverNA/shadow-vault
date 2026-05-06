# Shadow Vault

**Transparent AES-256-GCM encryption for Obsidian.** Your vault files stay encrypted on disk at all times. Obsidian sees and works with plaintext — search, graph view, Dataview, all plugins work as usual. No workflow changes required.

> ⚠️ **Desktop only** — uses Node.js `fs` and `crypto` modules not available on mobile.

---

## How it works

Shadow Vault patches Obsidian's file adapter (`app.vault.adapter`) to transparently redirect all file operations:

```
On disk (original vault):          Obsidian sees (shadow vault):
  note.md.enc  ──decrypt──►  /tmp/.shadow-vault-xxxx/note.md
  photo.png.enc              /tmp/.shadow-vault-xxxx/photo.png
```

- **Original vault** — stores only `.enc` files (AES-256-GCM, binary)
- **Shadow vault** — sibling directory created at session start, deleted on lock
- **Write-through** — every save encrypts back to the original vault immediately and atomically
- **Lazy decryption** — files are decrypted on demand; opened notes get highest priority

### Encryption format

```
[ IV (12 bytes) ][ Auth Tag (16 bytes) ][ Ciphertext ]
```

Key derivation: PBKDF2-SHA512, 310 000 iterations, 256-bit key, random 32-byte salt stored in `data.json`.

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
