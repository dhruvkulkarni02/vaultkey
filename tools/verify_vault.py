#!/usr/bin/env python3
"""
verify_vault.py
Small helper to check the vault integrity HMAC without attempting decryption.
Usage: python tools/verify_vault.py <vault_path> <password>

This will print whether the HMAC matches (i.e., password used to create the vault).
"""
import sys
import hmac
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # repo root

from vaultkey.storage import Storage


def main():
    if len(sys.argv) < 3:
        print("Usage: python tools/verify_vault.py <vault_path> <password>")
        sys.exit(2)

    vault_path = sys.argv[1]
    password = sys.argv[2]

    storage = Storage(vault_path)
    if not storage.exists():
        print(f"Vault not found: {vault_path}")
        sys.exit(1)

    version, data = storage.load()
    print(f"Loaded vault version: {version}, data length: {len(data)} bytes")

    if len(data) <= 40 or not data.startswith(b'VAULTKEY'):
        print("Vault does not appear to have the VAULTKEY integrity wrapper.")
        sys.exit(3)

    integrity_check = data[8:40]
    encrypted_data = data[40:]

    master_hash = hashlib.sha256(password.encode()).digest()
    expected = hmac.new(master_hash, encrypted_data, hashlib.sha256).digest()

    if hmac.compare_digest(integrity_check, expected):
        print("HMAC matches: the provided password appears to be the correct master password for integrity check.")
        sys.exit(0)
    else:
        print("HMAC does NOT match: the provided password is NOT the same as the one used to create the vault, or the vault data has been altered.")
        sys.exit(4)


if __name__ == '__main__':
    main()
