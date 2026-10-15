"""
errors.py - Exception types raised by VaultKey
"""


class VaultError(Exception):
    """Base class for all VaultKey errors"""


class VaultNotFoundError(VaultError):
    """No vault file exists at the configured path"""


class VaultExistsError(VaultError):
    """A vault already exists where a new one was to be created"""


class VaultLockedError(VaultError):
    """The operation needs an unlocked vault"""


class LockoutError(VaultError):
    """Too many failed unlock attempts; further attempts are refused for a while"""


class DecryptionError(VaultError):
    """Data could not be decrypted: wrong password, or the data was corrupted or tampered with"""


class VaultFormatError(VaultError):
    """The file is not a vault/backup VaultKey understands, or it is malformed"""
