"""
crypto.py - Handles all encryption and decryption operations
This is the security core of VaultKey
"""
import base64
import binascii
import json
import os
import struct
from typing import Dict, Iterator, Optional, Tuple

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .errors import DecryptionError, VaultFormatError

# Argon2id cost for newly encrypted data. The parameters are recorded in every
# envelope header, so they can be raised later without breaking existing vaults.
DEFAULT_KDF_PARAMS = {
    "time_cost": 3,         # iterations
    "memory_cost": 65536,   # KiB (64 MiB)
    "parallelism": 4,       # lanes
}

# Bounds applied to parameters read from a file, so a crafted header can't make
# us allocate gigabytes of memory or spin for hours before failing.
_KDF_LIMITS = {
    "time_cost": (1, 64),
    "memory_cost": (8 * 1024, 4 * 1024 * 1024),  # 8 MiB .. 4 GiB
    "parallelism": (1, 64),
}

SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32
ENVELOPE_VERSION = 1
_HEADER_LENGTH = struct.Struct(">H")


def derive_key(master_password: str, salt: bytes, kdf_params: Dict[str, int]) -> bytes:
    """Derive a 256-bit key from the master password with Argon2id."""
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=kdf_params["time_cost"],
        memory_cost=kdf_params["memory_cost"],
        parallelism=kdf_params["parallelism"],
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


class Crypto:
    """
    Encrypts data with AES-256-GCM under a key derived from the master password
    with Argon2id.

    Every ciphertext is a self-describing envelope:

        header length (2 bytes, big-endian) | header (JSON) | nonce (12 bytes) | ciphertext + tag

    The header records the KDF, its parameters and the salt, and is authenticated
    as associated data. An envelope can therefore be decrypted with nothing but
    the password - there is no separate salt file to lose.
    """

    def __init__(self):
        self.key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        self.kdf_params: Dict[str, int] = dict(DEFAULT_KDF_PARAMS)

    def create_key(
        self,
        master_password: str,
        salt: Optional[bytes] = None,
        kdf_params: Optional[Dict[str, int]] = None,
    ) -> None:
        """
        Derive the encryption key from the master password.

        A fresh random salt is generated unless one is given, so the same
        password produces a different key for every vault.
        """
        params = kdf_params or DEFAULT_KDF_PARAMS
        self.salt = salt if salt is not None else os.urandom(SALT_SIZE)
        self.kdf_params = {name: int(params[name]) for name in _KDF_LIMITS}
        self.key = derive_key(master_password, self.salt, self.kdf_params)

    @classmethod
    def from_envelope(cls, master_password: str, envelope: bytes) -> Tuple["Crypto", str]:
        """
        Derive the key described by an envelope's header and decrypt it.

        Returns:
            (crypto, plaintext) - the Crypto instance can re-encrypt with the same key

        Raises:
            DecryptionError: Wrong password, or the envelope was tampered with
            VaultFormatError: The envelope is malformed
        """
        header = _parse_envelope(envelope)[1]
        crypto = cls()
        crypto.create_key(master_password, header["salt"], header["kdf_params"])
        return crypto, crypto.decrypt(envelope)

    def encrypt(self, data: str) -> bytes:
        """Encrypt a string and return an envelope (see class docstring)."""
        if not self.key:
            raise ValueError("No encryption key set. Call create_key first.")

        header = json.dumps(
            {
                "v": ENVELOPE_VERSION,
                "kdf": "argon2id",
                "kdf_params": self.kdf_params,
                "salt": base64.b64encode(self.salt).decode("ascii"),
                "cipher": "aes-256-gcm",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        associated_data = _HEADER_LENGTH.pack(len(header)) + header

        # A random 96-bit nonce per encryption; the key changes whenever the
        # master password does, so nonce reuse is not a practical concern.
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(self.key).encrypt(nonce, data.encode("utf-8"), associated_data)
        return associated_data + nonce + ciphertext

    def decrypt(self, envelope: bytes) -> str:
        """
        Decrypt an envelope produced by encrypt() with the same key.

        Raises:
            DecryptionError: Wrong key, or the envelope was tampered with
            VaultFormatError: The envelope is malformed
        """
        if not self.key:
            raise ValueError("No encryption key set. Call create_key first.")

        associated_data, header, nonce, ciphertext = _parse_envelope(envelope)
        if header["salt"] != self.salt or header["kdf_params"] != self.kdf_params:
            raise DecryptionError("Data was encrypted with a different key")

        try:
            plaintext = AESGCM(self.key).decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise DecryptionError("Wrong password, or the data is corrupted") from None
        return plaintext.decode("utf-8")


def _parse_envelope(envelope: bytes) -> Tuple[bytes, Dict, bytes, bytes]:
    """Split an envelope into (associated data, validated header, nonce, ciphertext)."""
    if len(envelope) < _HEADER_LENGTH.size:
        raise VaultFormatError("Encrypted data is truncated")
    (header_length,) = _HEADER_LENGTH.unpack_from(envelope)
    header_end = _HEADER_LENGTH.size + header_length
    if len(envelope) < header_end + NONCE_SIZE + 16:
        raise VaultFormatError("Encrypted data is truncated")

    try:
        raw = json.loads(envelope[_HEADER_LENGTH.size:header_end].decode("utf-8"))
        if raw["v"] != ENVELOPE_VERSION:
            raise VaultFormatError(f"Unsupported envelope version: {raw['v']}")
        if raw["kdf"] != "argon2id" or raw["cipher"] != "aes-256-gcm":
            raise VaultFormatError(f"Unsupported algorithms: {raw['kdf']}/{raw['cipher']}")
        kdf_params = {name: int(raw["kdf_params"][name]) for name in _KDF_LIMITS}
        salt = base64.b64decode(raw["salt"], validate=True)
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, binascii.Error) as e:
        raise VaultFormatError(f"Malformed encryption header: {e}") from None

    for name, (low, high) in _KDF_LIMITS.items():
        if not low <= kdf_params[name] <= high:
            raise VaultFormatError(f"KDF parameter {name}={kdf_params[name]} is out of range")
    if kdf_params["memory_cost"] < 8 * kdf_params["parallelism"] or len(salt) < 16:
        raise VaultFormatError("Invalid KDF parameters")

    header = {"kdf_params": kdf_params, "salt": salt}
    nonce = envelope[header_end:header_end + NONCE_SIZE]
    return envelope[:header_end], header, nonce, envelope[header_end + NONCE_SIZE:]


# --- VaultKey 1.0.x compatibility -------------------------------------------------

# 1.0.x encrypted with Fernet, using a key derived with these Argon2id parameters
# (or with PBKDF2 when Argon2 failed), and kept the salt in a separate file.
LEGACY_KDF_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}


def legacy_decrypt(master_password: str, salt: bytes, token: bytes) -> str:
    """
    Decrypt a Fernet token written by VaultKey 1.0.x.

    Raises:
        DecryptionError: Wrong password, or the data is corrupted
    """
    for key in _legacy_keys(master_password, salt):
        try:
            return Fernet(key).decrypt(token).decode("utf-8")
        except InvalidToken:
            continue
    raise DecryptionError("Wrong password, or the data is corrupted")


def _legacy_keys(master_password: str, salt: bytes) -> Iterator[bytes]:
    """Candidate Fernet keys, in the order 1.0.x would have derived them."""
    yield base64.urlsafe_b64encode(derive_key(master_password, salt, LEGACY_KDF_PARAMS))
    # 1.0.x silently fell back to PBKDF2 whenever Argon2 raised, e.g. with
    # argon2-cffi < 23.1, whose PasswordHasher.hash() has no salt argument.
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    yield base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
