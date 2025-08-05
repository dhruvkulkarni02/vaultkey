"""
VaultKey - Military-grade password manager with enhanced security features.

Features:
- Argon2id memory-hard key derivation
- AES-256 encryption with integrity checking
- Account lockout protection
- Enhanced clipboard security
- Secure backup system
- Breach detection monitoring
"""

from .manager import PasswordManager
from .generator import generate_password
from .cli import cli

__version__ = "1.0.0"
__author__ = "Dhruv Kulkarni"
__email__ = "kulkarnidhruv02@gmail.com"
__license__ = "MIT"

__all__ = ["PasswordManager", "generate_password", "cli"]

# Security feature flags
FEATURES = {
    "argon2_kdf": True,
    "integrity_checking": True,
    "account_lockout": True,
    "enhanced_clipboard": True,
    "secure_backups": True,
    "breach_detection": True,
    "versioned_storage": True,
}

def get_version():
    """Get the current version string."""
    return __version__

def get_security_features():
    """Get list of enabled security features."""
    return [feature for feature, enabled in FEATURES.items() if enabled]
