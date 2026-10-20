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

- **Malware or another user with access to your account while the vault is unlocked.** They can read process memory, the clipboard, or record your keystrokes.
- **A weak master password.** Argon2id slows down guessing but cannot save a password that is easy to guess.
- **Copies of a 1.0.x vault file.** These contain a value that allows fast offline guessing. After upgrading, change your master password with `vk passwd`.
- **Plaintext exports.** Files written by `vk export-passwords --include-passwords` are not encrypted.

## Design

- **Key derivation:** Argon2id with a random 32-byte salt per vault, backup and export. The parameters and salt are stored in the file header.
- **Encryption:** AES-256-GCM with a random 96-bit nonce per write. The header is authenticated as associated data.
- **Storage:** writes are atomic (a temporary file with mode 0600, fsync, then rename).
- **Breach checks:** only the first 5 hex characters of the password's SHA-1 hash are sent to the HaveIBeenPwned range API, and responses are padded.
- **Clipboard:** clearing is done by a detached helper process. It receives a keyed fingerprint of the copied password, never the password itself.

VaultKey has not had an independent security audit.
