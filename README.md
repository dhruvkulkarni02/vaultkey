# VaultKey 🔐

[![PyPI version](https://badge.fury.io/py/vaultkey-cli.svg)](https://badge.fury.io/py/vaultkey-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Military-grade password manager with Argon2id encryption and zero-knowledge architecture**

VaultKey is a secure, offline password manager that keeps your passwords encrypted locally and never sends them to any server. Your master password is never stored anywhere, ensuring complete zero-knowledge security.

## 🚀 Features

- **🔒 Military-Grade Security**: Argon2id memory-hard key derivation with 64MB memory cost
- **🛡️ Zero-Knowledge Architecture**: Your passwords never leave your device
- **✅ Integrity Protection**: HMAC-SHA256 verification prevents tampering
- **🚫 Account Lockout Protection**: Automatic lockout after failed attempts
- **📋 Secure Clipboard**: Auto-clearing clipboard with original content restoration
- **🔄 Vault Versioning**: Backward compatibility with version management
- **💾 Secure Backups**: Independent encryption keys for backup files
- **🔍 Breach Detection**: Check passwords against known data breaches
- **📊 Security Auditing**: Comprehensive password strength analysis
- **🎯 Interactive Mode**: Professional CLI interface with color coding
- **📁 Import/Export**: Support for LastPass, 1Password, and other formats

## 📦 Installation

### Homebrew (macOS)
```bash
brew install vaultkey
```

### From PyPI
```bash
pip install vaultkey-cli
```

### From Source
```bash
git clone https://github.com/dhruvkulkarni02/vaultkey.git
cd vaultkey
pip install -r requirements.txt
```

## 🚀 Quick Start

```bash
# Initialize your vault (first time only)
vk init

# Add your first password (generates a secure password)
vk add -s github.com -u developer@email.com -g

# Copy password to clipboard
vk cp github
```

## 📖 Usage Examples

### Basic Password Management
```bash
# Add passwords
vk add -s github.com -u developer@email.com -g    # Generate password
vk add -s gmail.com -u myemail@gmail.com          # Enter manually

# Retrieve passwords
vk get -s github --show                           # Show password
vk get -s gmail --copy                            # Copy to clipboard
vk cp github                                      # Quick copy to clipboard

# Search passwords
vk search github                                  # Search by site/username
vk search --type weak                             # Find weak passwords
vk search --type old                              # Find old passwords

# List all passwords
vk list                                           # Basic list
vk list -f git                                    # Filter by 'git'
vk list -v                                        # Verbose with details
vk list --weak-only                               # Show only weak passwords
```

### Security Features
```bash
# Security audit
vk audit                                          # Basic strength audit
vk audit -v                                       # Verbose with details
vk audit -b                                       # Include breach checking
vk audit -w                                       # Show only weak passwords
vk audit -o                                       # Show only old passwords
vk audit -b -v                                    # Full audit with breaches

# Check for breached passwords
vk breaches                                       # Check all passwords
vk breaches -s github.com                         # Check specific site
vk breaches -v                                    # Verbose breach details

# Password generation
vk generate                                       # Generate with defaults
vk generate -l 24                                 # 24 characters
vk generate --no-symbols                          # No special characters
vk generate --no-ambiguous                        # Avoid confusing chars
vk generate -c 5                                  # Generate 5 passwords
```

### Advanced Features
```bash
# Import/Export
vk import-passwords ~/passwords.csv --format csv
vk import-passwords ~/lastpass.csv --format lastpass
vk export-passwords --format json --output backup.json

# Interactive mode
vk interactive                                    # Launch interactive UI

# Delete passwords
vk delete github.com                              # Delete with confirmation
vk delete github.com -f                           # Force delete
```

## 🔒 Security Overview

VaultKey implements industry-leading security practices:

- **Zero-Knowledge Architecture**: Master passwords are never stored
- **Argon2id Key Derivation**: Memory-hard function with 64MB memory cost
- **AES-256 Encryption**: Military-grade encryption for all data
- **HMAC-SHA256 Integrity**: Tamper detection for vault files
- **K-Anonymity**: Breach checking without exposing passwords
- **Secure Memory Handling**: Minimizes sensitive data exposure
- **Account Lockout**: Protection against brute-force attacks

## 📚 Command Reference

### Core Commands
| Command | Description |
|---------|-------------|
| `vk init` | Initialize a new password vault |
| `vk add` | Add a new password entry |
| `vk get` | Retrieve password by site name |
| `vk list` | Display all stored passwords |
| `vk search` | Search passwords by site/username/notes |
| `vk cp` | Quick copy password to clipboard |
| `vk delete` | Remove a password entry |

### Security Commands
| Command | Description |
|---------|-------------|
| `vk audit` | Comprehensive security audit |
| `vk breaches` | Check passwords against breach database |
| `vk generate` | Generate secure passwords |

### Data Management
| Command | Description |
|---------|-------------|
| `vk import-passwords` | Import from other password managers |
| `vk export-passwords` | Export passwords to file |
| `vk interactive` | Launch interactive mode |

## 🐍 Python API

```python
from vaultkey import PasswordManager

# Initialize the password manager
pm = PasswordManager()
pm.unlock("your-master-password")

# Add a password
pm.add_password("github.com", "username", "password123")

# Generate and store a secure password
secure_pass = pm.generate_password(length=20)
pm.add_password("example.com", "user@example.com", secure_pass)

# Retrieve a password
creds = pm.get_password("github.com")
print(f"Username: {creds['username']}")
print(f"Password: {creds['password']}")
```

## 📁 Project Structure

```
vaultkey/
├── vaultkey/
│   ├── __init__.py
│   ├── crypto.py          # Encryption/decryption logic
│   ├── storage.py         # Persistent storage handling
│   ├── generator.py       # Password generation utilities
│   ├── strength.py        # Password strength analysis
│   ├── breach.py          # Breach detection with HIBP
│   ├── portability.py     # Import/export functionality
│   ├── manager.py         # Main password manager class
│   └── cli.py             # Command-line interface
├── requirements.txt
├── setup.py
├── pyproject.toml
└── README.md
```

## 🛠️ Development

### Running Tests

```bash
# Run basic functionality test
python -c "from vaultkey.cli import cli; print('✅ VaultKey imports successfully')"

# Test password generation
python -c "from vaultkey.generator import generate_password; print('Generated:', generate_password(16))"
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Security Vulnerabilities

If you discover a security vulnerability, please open a private security advisory instead of a public issue.

## 🗺️ Roadmap

### Completed ✅
- [x] Argon2id encryption with 64MB memory cost
- [x] Command-line interface with 10+ commands
- [x] Password generation with customizable options
- [x] Password strength analysis and scoring
- [x] Breach detection (HaveIBeenPwned integration)
- [x] Import/export functionality (CSV, JSON, LastPass, etc.)
- [x] Interactive mode with professional UI
- [x] HMAC-SHA256 integrity verification

### Planned 📋
- [ ] Desktop GUI application
- [ ] Browser extension
- [ ] Secure password sharing
- [ ] Cloud sync with end-to-end encryption
- [ ] Biometric unlock (TouchID/FaceID)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [cryptography](https://cryptography.io/) - Encryption library
- [HaveIBeenPwned](https://haveibeenpwned.com/) - Breach detection API
- [Click](https://click.palletsprojects.com/) - CLI framework
- [tabulate](https://pypi.org/project/tabulate/) - Table formatting

---

**⚠️ Security Notice**: While VaultKey implements industry-standard security practices, for mission-critical use cases consider established, audited password managers.

**🔑 Remember**: Use a strong master password and never share it with anyone!