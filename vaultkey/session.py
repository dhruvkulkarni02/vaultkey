"""
session.py - Keep the vault unlocked between commands (`vk unlock` / `vk lock`)

`vk unlock` derives the vault key once, encrypts it under a random session
token, and writes the result next to the vault (owner-only). The token is
printed for the user to export as VAULTKEY_SESSION. Later commands need both
the file and the token, so the key is useless to anyone who only has the disk,
and `vk lock` (or the inactivity timeout) ends the session for every shell.
"""
import base64
import binascii
import json
import os
import secrets
import time
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import Crypto
from .storage import Storage

SESSION_ENV = "VAULTKEY_SESSION"
DEFAULT_TIMEOUT_MINUTES = 15
_ASSOCIATED_DATA = b"vaultkey-session-v1"


def session_file(vault_path: str) -> str:
    """Session file belonging to a vault"""
    return os.path.abspath(vault_path) + ".session"


def start_session(crypto: Crypto, vault_path: str, timeout_minutes: int = DEFAULT_TIMEOUT_MINUTES) -> str:
    """
    Store the vault key for later commands.

    Args:
        crypto: Crypto instance holding the unlocked vault's key
        vault_path: Path of the vault
        timeout_minutes: Session ends after this many minutes without use

    Returns:
        The session token to export as VAULTKEY_SESSION
    """
    token = secrets.token_bytes(32)
    _write(token, vault_path, {
        "vault": os.path.abspath(vault_path),
        "key": base64.b64encode(crypto.key).decode(),
        "salt": base64.b64encode(crypto.salt).decode(),
        "kdf_params": crypto.kdf_params,
        "timeout": timeout_minutes * 60,
        "expires": time.time() + timeout_minutes * 60,
    })
    return base64.urlsafe_b64encode(token).decode()


def resume_session(vault_path: str, token: Optional[str] = None) -> Optional[Crypto]:
    """
    Return a Crypto holding the vault key if a valid session exists, else None.

    Each successful use extends the session by its timeout.
    """
    token = token if token is not None else os.environ.get(SESSION_ENV)
    path = session_file(vault_path)
    if not token or not os.path.exists(path):
        return None

    try:
        raw_token = base64.urlsafe_b64decode(token.encode())
        blob = Storage(path).load()[1]
        session = json.loads(AESGCM(raw_token).decrypt(blob[:12], blob[12:], _ASSOCIATED_DATA))
    except (ValueError, binascii.Error, InvalidTag):
        return None  # Token from another session, or a damaged file

    if session.get("vault") != os.path.abspath(vault_path):
        return None
    if time.time() > session["expires"]:
        end_session(vault_path)
        return None

    session["expires"] = time.time() + session["timeout"]
    _write(raw_token, vault_path, session)

    crypto = Crypto()
    crypto.key = base64.b64decode(session["key"])
    crypto.salt = base64.b64decode(session["salt"])
    crypto.kdf_params = session["kdf_params"]
    return crypto


def session_expiry(vault_path: str, token: Optional[str] = None) -> Optional[float]:
    """Expiry time of the active session (without extending it), or None"""
    token = token if token is not None else os.environ.get(SESSION_ENV)
    path = session_file(vault_path)
    if not token or not os.path.exists(path):
        return None
    try:
        blob = Storage(path).load()[1]
        session = json.loads(AESGCM(base64.urlsafe_b64decode(token.encode())).decrypt(
            blob[:12], blob[12:], _ASSOCIATED_DATA))
    except (ValueError, binascii.Error, InvalidTag):
        return None
    return session["expires"] if session["expires"] > time.time() else None


def end_session(vault_path: str) -> bool:
    """Delete the session file. Returns True if a session existed."""
    path = session_file(vault_path)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def _write(token: bytes, vault_path: str, session: dict) -> None:
    nonce = os.urandom(12)
    ciphertext = AESGCM(token).encrypt(nonce, json.dumps(session).encode(), _ASSOCIATED_DATA)
    Storage(session_file(vault_path)).save(nonce + ciphertext)
