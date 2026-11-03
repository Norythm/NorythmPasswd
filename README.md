# NorythmPasswd (np)

A lightweight, local-first password manager and two-factor authenticator CLI written in Rust.

NorythmPasswd gives you full ownership over your credentials. There are no proprietary cloud services, mandatory accounts, or telemetry trackers. All data remains encrypted on your local machine using modern cryptographic standards.

---

## Core Capabilities

- **Authenticated Local Encryption**: Vault data is encrypted with AES-256-GCM and derived via memory-hard Argon2id (64 MiB, 3 iterations, 4 lanes) to resist offline GPU brute-force attacks.
- **Built-in TOTP Authenticator**: Live RFC 6238 two-factor authentication code generator with remaining time indicators and automated clipboard export.
- **In-Memory Zeroization**: Master passwords, derived encryption keys, and decrypted credentials are automatically cleared from RAM using `zeroize` upon process completion or vault lock.
- **Secure Clipboard Integration**: Piped via standard input directly to `wl-copy` on Wayland, `xclip`/`xsel` on X11, or the Win32 clipboard API on Windows. Credentials are never passed via command-line arguments and automatically clear after 20 seconds.
- **Automated Backup Sync**: Maintains synchronized copies in encrypted archives, raw JSON, human-readable text, Markdown, and CSV on every write operation.
- **Data Portability**: Import and export your accounts to and from encrypted standalone vaults (`.vault`, `.enc`), raw JSON, and Bitwarden-compatible CSV.
- **Configurable Runtime Path**: Manage your active vault location across local drives, mounted partitions, or removable USB storage via `np path`.

---

## Installation

### Prerequisites

Install Rust and Cargo using `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build from Source

```bash
git clone https://github.com/Norythm/NorythmPasswd.git
cd NorythmPasswd
cargo build --release -p np
cp target/release/np ~/.local/bin/
```

Ensure `~/.local/bin` is in your system `PATH`.

---

## Command Reference

| Command | Description |
| :--- | :--- |
| `np list [query]` | Search and display accounts grouped by section |
| `np get <service>` | Copy account password to clipboard (clears in 20s) |
| `np get <service> --totp` | Copy current two-factor authentication code to clipboard |
| `np get <service> --codes` | View and copy 2FA emergency backup recovery codes |
| `np get <service> --show` | Display account password in the terminal |
| `np totp <service>` | Generate and copy live two-factor authentication code |
| `np codes [service]` | List all 2FA backup codes or view/copy codes for a specific service |
| `np codes <service> --add` | Add or update emergency backup recovery codes |
| `np codes <service> --rm` | Remove backup codes for a service |
| `np add [service]` | Add an account interactively with optional password generation |
| `np edit <service>` | Modify username, password, section, notes, or TOTP secret |
| `np rm <service>` | Delete an account from the vault |
| `np passgen [-l 20]` | Generate cryptographically secure random passwords |
| `np path [new_path]` | Inspect or update the runtime database path |
| `np backup [folder]` | Generate timestamped backups in encrypted and decrypted formats |
| `np export` | Export vault data to `.json`, `.csv`, `.md`, `.txt`, or `.vault` |
| `np import <file>` | Import credentials from backup archives, JSON, or CSV |

---

## Security Specifications

| Layer | Implementation | Details |
| :--- | :--- | :--- |
| Key Derivation | Argon2id | 64 MiB RAM cost, 3 iterations, 4 parallel lanes, 16-byte random salt |
| Symmetric Encryption | AES-256-GCM | 16-byte random IV, 16-byte authentication tag |
| Legacy Compatibility | PBKDF2-HMAC-SHA256 | Dual-KDF decryption with automatic in-place migration to Argon2id |
| RAM Protection | zeroize crate | Explicit buffer wipe on drop across keys and decrypted entries |
| Clipboard Security | Stdin piping | Sensitive flags set; detached auto-purge timer (20s) |
| License Verification | Ed25519 | Asymmetric public-key signature verification |

---

## License

Copyright (c) 2026 Norythm. All Rights Reserved.

This software is proprietary and source-available for personal use and security verification only. Commercial use, reproduction, redistribution, and sublicensing are strictly prohibited without prior written permission. See [LICENSE](LICENSE) for details.
