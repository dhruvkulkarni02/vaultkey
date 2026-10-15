import base64
import hashlib
import hmac

import argon2
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from vaultkey import crypto

# Smallest parameters the envelope parser accepts, so tests stay fast
FAST_KDF_PARAMS = {"time_cost": 1, "memory_cost": 8192, "parallelism": 1}


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(crypto, "DEFAULT_KDF_PARAMS", FAST_KDF_PARAMS)


@pytest.fixture
def vault_path(tmp_path):
    return str(tmp_path / "vault" / "passwords.encrypted")


def legacy_fernet_key(password, salt, kdf="argon2"):
    """Derive a key exactly the way VaultKey 1.0.x did"""
    if kdf == "argon2":
        hasher = argon2.PasswordHasher(
            time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=32
        )
        key_bytes = hasher.hash(password, salt=salt).split('$')[-1].encode()
        return base64.urlsafe_b64encode(base64.b64decode(key_bytes + b'=='))
    pbkdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(pbkdf2.derive(password.encode()))


def write_legacy_vault(path, password, vault_data, version=2, kdf="argon2", with_hmac=True):
    """Write a vault + salt.bin in the VaultKey 1.0.x on-disk format"""
    import json
    import os

    salt = os.urandom(32)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(os.path.join(os.path.dirname(path), "salt.bin"), "wb") as f:
        f.write(salt)

    token = Fernet(legacy_fernet_key(password, salt, kdf)).encrypt(json.dumps(vault_data).encode())
    if version == 1:
        body = token
    else:
        if with_hmac:
            tag = hmac.new(hashlib.sha256(password.encode()).digest(), token, hashlib.sha256).digest()
            token = b"VAULTKEY" + tag + token
        body = b"VAULTKEY_V2:" + token
    with open(path, "wb") as f:
        f.write(body)
    return salt
