import os
import stat
import time

import pytest

from vaultkey import session
from vaultkey.manager import PasswordManager

MASTER = "correct horse battery staple"


@pytest.fixture
def unlocked(vault_path):
    pm = PasswordManager(vault_path)
    pm.create_vault(MASTER)
    pm.add_password("github.com", "octocat", "gh-secret")
    return pm


def test_session_unlocks_without_password(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path)
    crypto = session.resume_session(vault_path, token)
    assert crypto is not None

    pm = PasswordManager(vault_path)
    assert pm.unlock_with_crypto(crypto)
    assert pm.get_password("github.com")["password"] == "gh-secret"


def test_session_file_does_not_contain_the_key_in_clear(unlocked, vault_path):
    session.start_session(unlocked.crypto, vault_path)
    with open(session.session_file(vault_path), "rb") as f:
        data = f.read()
    assert unlocked.crypto.key not in data
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(session.session_file(vault_path)).st_mode) == 0o600


def test_wrong_or_missing_token_gives_nothing(unlocked, vault_path):
    session.start_session(unlocked.crypto, vault_path)
    other_token = session.start_session.__globals__["base64"].urlsafe_b64encode(os.urandom(32)).decode()
    assert session.resume_session(vault_path, other_token) is None
    assert session.resume_session(vault_path, "") is None
    assert session.resume_session(vault_path, "not base64 !!") is None


def test_session_expires_after_inactivity(unlocked, vault_path, monkeypatch):
    token = session.start_session(unlocked.crypto, vault_path, timeout_minutes=1)
    now = time.time()

    monkeypatch.setattr(session.time, "time", lambda: now + 50)
    assert session.resume_session(vault_path, token) is not None  # extends to now + 110

    monkeypatch.setattr(session.time, "time", lambda: now + 100)
    assert session.resume_session(vault_path, token) is not None

    monkeypatch.setattr(session.time, "time", lambda: now + 500)
    assert session.resume_session(vault_path, token) is None
    assert not os.path.exists(session.session_file(vault_path))  # expired file is removed


def test_end_session(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path)
    assert session.end_session(vault_path) is True
    assert session.resume_session(vault_path, token) is None
    assert session.end_session(vault_path) is False


def test_session_is_bound_to_its_vault(unlocked, vault_path, tmp_path):
    token = session.start_session(unlocked.crypto, vault_path)
    other_vault = str(tmp_path / "other" / "passwords.encrypted")
    os.makedirs(os.path.dirname(other_vault))
    os.replace(session.session_file(vault_path), session.session_file(other_vault))
    assert session.resume_session(other_vault, token) is None


def test_session_key_stops_working_after_password_change(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path)
    unlocked.change_master_password(MASTER, "another long master password")

    crypto = session.resume_session(vault_path, token)
    assert crypto is not None  # the session file itself is still readable...
    assert PasswordManager(vault_path).unlock_with_crypto(crypto) is False  # ...but the key no longer fits
