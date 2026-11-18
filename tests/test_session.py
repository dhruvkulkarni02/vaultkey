import base64
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


def wait_until(condition, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return False


def test_session_unlocks_without_password(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path)
    crypto = session.resume_session(vault_path, token)
    assert crypto is not None

    pm = PasswordManager(vault_path)
    assert pm.unlock_with_crypto(crypto)
    assert pm.get_password("github.com")["password"] == "gh-secret"


def test_nothing_secret_is_written_to_disk(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path)
    with open(session.session_file(vault_path), "rb") as f:
        data = f.read()
    for secret in (unlocked.crypto.key, base64.b64encode(unlocked.crypto.key), token.encode(),
                   base64.urlsafe_b64decode(token)):
        assert secret not in data
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(session.session_file(vault_path)).st_mode) == 0o600


def test_wrong_or_missing_token_gives_nothing(unlocked, vault_path):
    session.start_session(unlocked.crypto, vault_path)
    other_token = base64.urlsafe_b64encode(os.urandom(32)).decode()
    assert session.resume_session(vault_path, other_token) is None
    assert session.resume_session(vault_path, "") is None
    assert session.resume_session(vault_path, "not base64 !!") is None


def test_session_expires_after_inactivity(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path, timeout_minutes=4 / 60)
    for _ in range(3):  # each use extends the session, so 6s of use outlives a 4s timeout
        time.sleep(2)
        assert session.resume_session(vault_path, token) is not None

    # Once idle for longer than the timeout, the agent exits and the key is gone
    assert wait_until(lambda: not os.path.exists(session.session_file(vault_path)))
    assert session.resume_session(vault_path, token) is None


def test_expiry_is_reported_without_extending(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path, timeout_minutes=1)
    expires = session.session_expiry(vault_path, token)
    assert time.time() < expires <= time.time() + 60
    assert session.session_expiry(vault_path, token) == expires


def test_end_session(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path)
    assert session.end_session(vault_path) is True
    assert session.resume_session(vault_path, token) is None
    assert session.end_session(vault_path) is False


def test_lock_stops_the_agent_even_with_a_copied_session_file(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path)
    with open(session.session_file(vault_path), "rb") as f:
        copy = f.read()
    session.end_session(vault_path)
    time.sleep(session._WATCH_INTERVAL * 4)

    # Putting the file back doesn't revive the session: the agent has exited
    with open(session.session_file(vault_path), "wb") as f:
        f.write(copy)
    assert session.resume_session(vault_path, token) is None


def test_new_unlock_replaces_the_old_session(unlocked, vault_path):
    old_token = session.start_session(unlocked.crypto, vault_path)
    new_token = session.start_session(unlocked.crypto, vault_path)
    assert session.resume_session(vault_path, old_token) is None
    assert session.resume_session(vault_path, new_token) is not None


def test_session_is_bound_to_its_vault(unlocked, vault_path, tmp_path):
    token = session.start_session(unlocked.crypto, vault_path)
    other_vault = str(tmp_path / "other" / "passwords.encrypted")
    os.makedirs(os.path.dirname(other_vault))
    with open(session.session_file(vault_path), "rb") as src, open(session.session_file(other_vault), "wb") as dst:
        dst.write(src.read())
    assert session.resume_session(other_vault, token) is None


def test_session_key_stops_working_after_password_change(unlocked, vault_path):
    token = session.start_session(unlocked.crypto, vault_path)
    unlocked.change_master_password(MASTER, "another long master password")

    crypto = session.resume_session(vault_path, token)
    assert crypto is not None  # the agent still runs (vk passwd also ends it)...
    assert PasswordManager(vault_path).unlock_with_crypto(crypto) is False  # ...but its key no longer fits
