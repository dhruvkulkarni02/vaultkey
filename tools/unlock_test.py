#!/usr/bin/env python3
"""
unlock_test.py
Helper to attempt to unlock a vault file using PasswordManager API.
Usage: python tools/unlock_test.py <vault_path> <password> [salt_path]

If `salt_path` is provided, the script will copy it to the current working
directory as `salt.bin` (temporarily) so the Crypto class can find it.

This script does not modify the original vault file; it only attempts to
unlock and will print basic vault metadata if successful.
"""
import sys
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaultkey.manager import PasswordManager


def main():
    if len(sys.argv) < 3:
        print("Usage: python tools/unlock_test.py <vault_path> <password> [salt_path]")
        sys.exit(2)

    vault_path = sys.argv[1]
    password = sys.argv[2]
    salt_path = sys.argv[3] if len(sys.argv) > 3 else None

    # Prepare working copy of salt if provided
    if salt_path:
        salt_file = Path(salt_path)
        if not salt_file.exists():
            print(f"Salt file not found: {salt_path}")
            sys.exit(3)
        # copy to cwd as 'salt.bin' (this is what Crypto expects by default)
        shutil.copy2(salt_file, Path('salt.bin'))
        print(f"Copied salt file to ./salt.bin (temporary)")

    try:
        pm = PasswordManager(vault_path)
        print(f"Attempting to unlock: {vault_path}")
        ok = pm.unlock(password)
        if ok:
            print("Unlock successful.")
            info = pm.get_vault_info()
            print(f"Vault metadata: version={info['version']}, created={info['created']}, passwords={info['password_count']}")
            # Do not dump passwords
            pm.lock()
            sys.exit(0)
        else:
            print("Unlock failed: wrong password or corrupted data.")
            sys.exit(4)
    except Exception as e:
        print(f"Error during unlock: {e}")
        sys.exit(5)


if __name__ == '__main__':
    main()
