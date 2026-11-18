# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ |
| 1.0.x   | ❌ Upgrade to 2.x: the 1.0.x vault format allows fast offline guessing of the master password |

## Reporting a Vulnerability

Please report vulnerabilities privately, not in a public issue. Open a GitHub security advisory for this repository, from the **Security** tab under **Report a vulnerability**.

Include the VaultKey version, your OS, and steps to reproduce. You should get a reply within a week.

## Threat Model

VaultKey protects the vault file at rest. Someone who obtains a copy of the vault file, for example from a backup, a synced folder or a stolen disk, should not be able to read it without the master password. The only way for them to test a master-password guess is to run Argon2id (64 MB memory, 3 iterations) and attempt decryption.

What VaultKey does **not** protect against:

- **Malware or another user with access to your account while the vault is unlocked**, including while a `vk unlock` session is active. They can read process memory, the clipboard, or record your keystrokes.
- **A weak master password.** Argon2id slows down guessing but cannot save a password that is easy to guess.
- **Copies of a 1.0.x vault file.** These contain a value that allows fast offline guessing. After upgrading, change your master password with `vk passwd`.
- **Plaintext exports.** Files written by `vk export-passwords --include-passwords` are not encrypted.

## Design

- **Key derivation:** Argon2id with a random 32-byte salt per vault, backup and export. The parameters and salt are stored in the file header.
- **Encryption:** AES-256-GCM with a random 96-bit nonce per write. The header is authenticated as associated data.
- **Storage:** writes are atomic (a temporary file with mode 0600, fsync, then rename).
- **Breach checks:** only the first 5 hex characters of the password's SHA-1 hash are sent to the HaveIBeenPwned range API, and responses are padded.
- **Sessions (`vk unlock`):** the vault key is handed to a detached agent process that holds it in memory only. Commands connect to it over a Unix socket in a private (0700) directory, or a named pipe on Windows, and authenticate with an HMAC challenge-response keyed by a random 256-bit token; the token is held only in the shell's `VAULTKEY_SESSION` variable and is never sent. The `<vault>.session` file (0600) records only the agent's address. The agent exits when the session has been idle for its timeout (15 minutes by default), when `vk lock` or `vk passwd` removes that file, or at restart, so an old token or a copied file is useless afterwards. While a session is active, every program started from that shell inherits the token and can fetch the vault key, which opens the vault until the master password changes. Lock the session before running code you don't trust.
- **Clipboard:** clearing is done by a detached helper process. It receives a keyed fingerprint of the copied password, never the password itself. Helpers are started so that Python modules in the current directory can't be loaded into them.
- **Releases:** the standalone executables aren't code-signed. Each release lists their SHA-256 checksums in `SHA256SUMS.txt` and has signed build provenance, which `gh attestation verify` checks.

VaultKey has not had an independent security audit.
