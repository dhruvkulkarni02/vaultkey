import json
import struct

import pytest

from vaultkey.crypto import Crypto, legacy_decrypt
from vaultkey.errors import DecryptionError, VaultFormatError

from conftest import FAST_KDF_PARAMS, legacy_fernet_key


def make_crypto(password="hunter2-but-longer"):
    c = Crypto()
    c.create_key(password)
    return c


def test_roundtrip_and_self_describing_envelope():
    c = make_crypto()
    envelope = c.encrypt("secret data ✓")
    assert c.decrypt(envelope) == "secret data ✓"

    # A fresh instance needs nothing but the password
    other, plaintext = Crypto.from_envelope("hunter2-but-longer", envelope)
    assert plaintext == "secret data ✓"
    assert other.salt == c.salt and other.kdf_params == FAST_KDF_PARAMS


def test_every_encryption_uses_a_fresh_nonce():
    c = make_crypto()
    assert c.encrypt("same") != c.encrypt("same")


def test_new_keys_get_fresh_salts():
    assert make_crypto().salt != make_crypto().salt


def test_wrong_password_raises():
    envelope = make_crypto().encrypt("x")
    with pytest.raises(DecryptionError):
        Crypto.from_envelope("wrong", envelope)


def test_tampered_ciphertext_is_rejected():
    c = make_crypto()
    envelope = bytearray(c.encrypt("hello"))
    envelope[-1] ^= 1
    with pytest.raises(DecryptionError):
        c.decrypt(bytes(envelope))


def _rewrite_header(envelope, change):
    (length,) = struct.unpack_from(">H", envelope)
    header = json.loads(envelope[2:2 + length])
    change(header)
    raw = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return struct.pack(">H", len(raw)) + raw + envelope[2 + length:]


def test_tampered_header_is_rejected():
    envelope = make_crypto().encrypt("hello")
    # Same values, different encoding: the header is authenticated byte-for-byte
    (length,) = struct.unpack_from(">H", envelope)
    reformatted = envelope[2:2 + length].replace(b'"v":1', b'"v": 1')
    tampered = struct.pack(">H", len(reformatted)) + reformatted + envelope[2 + length:]
    with pytest.raises(DecryptionError):
        Crypto.from_envelope("hunter2-but-longer", tampered)


def test_absurd_kdf_parameters_are_refused_before_deriving():
    envelope = _rewrite_header(
        make_crypto().encrypt("x"),
        lambda h: h["kdf_params"].update(memory_cost=2 ** 31),
    )
    with pytest.raises(VaultFormatError):
        Crypto.from_envelope("hunter2-but-longer", envelope)


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x05{}", b"\xff\xff" + b"x" * 40])
def test_malformed_envelopes_raise_format_error(data):
    with pytest.raises(VaultFormatError):
        Crypto.from_envelope("pw", data)


def test_encrypt_without_key_raises():
    with pytest.raises(ValueError):
        Crypto().encrypt("x")


@pytest.mark.parametrize("kdf", ["argon2", "pbkdf2"])
def test_legacy_decrypt_handles_both_1_0_key_derivations(kdf):
    from cryptography.fernet import Fernet

    salt = b"s" * 32
    token = Fernet(legacy_fernet_key("old-pw", salt, kdf)).encrypt(b"legacy")
    assert legacy_decrypt("old-pw", salt, token) == "legacy"
    with pytest.raises(DecryptionError):
        legacy_decrypt("wrong", salt, token)
