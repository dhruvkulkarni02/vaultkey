import hashlib
import hmac
import os

import pytest

from vaultkey.errors import (
    LockoutError,
    VaultExistsError,
    VaultFormatError,
    VaultLockedError,
)
from vaultkey.manager import PasswordManager, default_vault_path
from vaultkey.storage import CURRENT_VERSION

from conftest import write_legacy_vault

MASTER = "correct horse battery staple"


@pytest.fixture
def pm(vault_path):
    manager = PasswordManager(vault_path)
    manager.create_vault(MASTER)
    manager.add_password("github.com", "octocat", "gh-secret", "work account")
    return manager


def reopen(path, password=MASTER):
    manager = PasswordManager(path)
    assert manager.unlock(password)
    return manager


def test_create_add_and_reopen(pm, vault_path):
    other = reopen(vault_path)
    assert other.get_password("github.com")["password"] == "gh-secret"
    assert other.get_password("github.com")["notes"] == "work account"


def test_vault_is_single_self_contained_file(pm, vault_path):
    assert os.listdir(os.path.dirname(vault_path)) == ["passwords.encrypted"]


def test_create_refuses_existing_vault_and_empty_password(pm, vault_path, tmp_path):
    with pytest.raises(VaultExistsError):
        PasswordManager(vault_path).create_vault(MASTER)
    with pytest.raises(ValueError):
        PasswordManager(str(tmp_path / "other")).create_vault("")


def test_vault_file_has_no_fast_password_verifier(pm, vault_path):
    """1.0.x stored HMAC(SHA-256(password), ...), allowing offline guessing without Argon2"""
    with open(vault_path, "rb") as f:
        data = f.read()
    assert data.startswith(f"VAULTKEY_V{CURRENT_VERSION}:".encode())
    assert b"VAULTKEY" not in data[len("VAULTKEY_V3:"):]

    fast_key = hashlib.sha256(MASTER.encode()).digest()
    for start in range(len(data) - 32):
        body = data[start + 32:]
        if body and hmac.new(fast_key, body, hashlib.sha256).digest() == data[start:start + 32]:
            pytest.fail("vault contains an HMAC keyed by SHA-256(master password)")


def test_wrong_password_counts_once(pm, vault_path):
    other = PasswordManager(vault_path)
    assert other.unlock("wrong") is False
    assert other.failed_attempts == 1
    assert not other.is_unlocked()


def test_lockout_after_max_attempts(pm, vault_path):
    other = PasswordManager(vault_path)
    for _ in range(other.max_attempts - 1):
        assert other.unlock("wrong") is False
    with pytest.raises(LockoutError):
        other.unlock("wrong")
    # Even the right password is refused during the lockout
    with pytest.raises(LockoutError):
        other.unlock(MASTER)


def test_locked_vault_refuses_access(pm):
    pm.lock()
    with pytest.raises(VaultLockedError):
        pm.get_password("github.com")


def test_update_keeps_history(pm):
    pm.update_password("github.com", new_password="second")
    assert pm.get_password_history("github.com")[0]["password"] == "gh-secret"
    assert pm.check_password_reuse("github.com", "gh-secret")


def test_change_master_password(pm, vault_path):
    assert pm.change_master_password("wrong", "new-master") is False
    assert pm.change_master_password(MASTER, "new-master") is True
    assert PasswordManager(vault_path).unlock(MASTER) is False
    assert reopen(vault_path, "new-master").get_password("github.com")["password"] == "gh-secret"


def test_import_entries_skips_existing(pm):
    imported, skipped = pm.import_entries({
        "github.com": {"username": "x", "password": "y"},
        "gitlab.com": {"username": "u", "password": "p"},
    })
    assert imported == ["gitlab.com"] and skipped == ["github.com"]
    assert pm.get_password("github.com")["password"] == "gh-secret"


# --- backups ---------------------------------------------------------------

def test_backup_is_self_contained_and_restores_on_new_machine(pm, tmp_path):
    backup = str(tmp_path / "backups" / "vault.vkbak")
    pm.create_secure_backup("backup-pw", backup)
    assert os.listdir(tmp_path / "backups") == ["vault.vkbak"]

    new_vault = str(tmp_path / "new-machine" / "passwords.encrypted")
    fresh = PasswordManager(new_vault)
    fresh.restore_from_backup(backup, "backup-pw", master_password="new-master")

    assert reopen(new_vault, "new-master").get_password("github.com")["password"] == "gh-secret"


def test_restore_into_unlocked_vault_keeps_master_password(pm, vault_path, tmp_path):
    backup = str(tmp_path / "vault.vkbak")
    pm.create_secure_backup("backup-pw", backup)
    pm.delete_password("github.com")

    pm.restore_from_backup(backup, "backup-pw")
    assert reopen(vault_path).get_password("github.com")["password"] == "gh-secret"


def test_restore_needs_unlocked_vault_or_master_password(pm, tmp_path):
    backup = str(tmp_path / "vault.vkbak")
    pm.create_secure_backup("backup-pw", backup)
    with pytest.raises(VaultLockedError):
        PasswordManager(str(tmp_path / "fresh")).restore_from_backup(backup, "backup-pw")


def test_restore_with_wrong_backup_password_changes_nothing(pm, vault_path, tmp_path):
    from vaultkey.errors import DecryptionError

    backup = str(tmp_path / "vault.vkbak")
    pm.create_secure_backup("backup-pw", backup)
    before = open(vault_path, "rb").read()
    with pytest.raises(DecryptionError):
        pm.restore_from_backup(backup, "wrong")
    assert open(vault_path, "rb").read() == before


# --- migration from 1.0.x --------------------------------------------------

LEGACY_DATA = {
    "version": "1.1",
    "created": "2024-01-01T00:00:00",
    "passwords": {"site.com": {"username": "me", "password": "old-secret", "notes": "",
                               "created": "", "modified": "", "history": []}},
    "settings": {"history_enabled": True, "max_history_items": 10},
}


@pytest.mark.parametrize("version,kdf,with_hmac", [
    (2, "argon2", True),
    (2, "argon2", False),
    (2, "pbkdf2", True),
    (1, "argon2", False),
])
def test_legacy_vault_is_migrated_on_unlock(vault_path, version, kdf, with_hmac):
    write_legacy_vault(vault_path, MASTER, LEGACY_DATA, version, kdf, with_hmac)

    manager = PasswordManager(vault_path)
    assert manager.unlock("wrong") is False
    assert manager.unlock(MASTER)
    assert manager.migrated_from_version == version
    assert manager.get_password("site.com")["password"] == "old-secret"

    with open(vault_path, "rb") as f:
        assert f.read().startswith(b"VAULTKEY_V3:")
    # The migrated vault no longer needs salt.bin
    os.remove(os.path.join(os.path.dirname(vault_path), "salt.bin"))
    assert reopen(vault_path).get_password("site.com")["password"] == "old-secret"


def test_legacy_vault_without_salt_file_reports_it(vault_path):
    write_legacy_vault(vault_path, MASTER, LEGACY_DATA)
    salt_file = os.path.join(os.path.dirname(vault_path), "salt.bin")
    os.remove(salt_file)

    with pytest.raises(VaultFormatError, match="salt"):
        PasswordManager(vault_path).unlock(MASTER)
    assert not os.path.exists(salt_file)  # never invents a new salt


def test_legacy_backup_with_salt_sidecar_restores(tmp_path, vault_path):
    import json
    from cryptography.fernet import Fernet
    from conftest import legacy_fernet_key

    backup = str(tmp_path / "old.vkbak")
    salt = os.urandom(32)
    with open(backup + ".salt", "wb") as f:
        f.write(salt)
    payload = {"backup_type": "secure_backup", "backup_date": "2024-02-02", "data": LEGACY_DATA}
    token = Fernet(legacy_fernet_key("backup-pw", salt)).encrypt(json.dumps(payload).encode())
    with open(backup, "wb") as f:
        f.write(b"VAULTKEY_V2:" + token)

    manager = PasswordManager(vault_path)
    assert manager.restore_from_backup(backup, "backup-pw", master_password=MASTER) == "2024-02-02"
    assert reopen(vault_path).get_password("site.com")["password"] == "old-secret"


def test_default_vault_path_honours_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULTKEY_VAULT", str(tmp_path / "custom.vault"))
    assert default_vault_path() == str(tmp_path / "custom.vault")
    monkeypatch.delenv("VAULTKEY_VAULT")
    assert default_vault_path().endswith(os.path.join(".vaultkey", "passwords.encrypted"))


def test_failed_reverification_keeps_session_unlocked(pm):
    assert pm.change_master_password("wrong", "new") is False
    assert pm.is_unlocked()
    assert pm.get_password("github.com")["password"] == "gh-secret"
