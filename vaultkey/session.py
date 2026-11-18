"""
session.py - Keep the vault unlocked between commands (`vk unlock` / `vk lock`)

`vk unlock` hands the vault key to a small background agent process, which
keeps it in memory only. Later commands fetch the key from the agent over a
local socket (a named pipe on Windows) by proving, with a challenge-response,
that they know the session token printed for VAULTKEY_SESSION; the token itself
is never sent. The agent exits, and the key is gone, once the session has been
idle for its timeout, on `vk lock`, or when the computer restarts.

The only file is `<vault>.session`, which holds the agent's address and nothing
secret. Removing it is how `vk lock` ends the session from any shell.
"""
import base64
import binascii
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from multiprocessing.connection import (
    AuthenticationError,
    Client,
    Listener,
    answer_challenge,
    deliver_challenge,
)
from typing import Optional

from .crypto import Crypto
from .helpers import spawn_helper

SESSION_ENV = "VAULTKEY_SESSION"
DEFAULT_TIMEOUT_MINUTES = 15
_WATCH_INTERVAL = 0.5  # seconds between the agent's checks for expiry and `vk lock`


def session_file(vault_path: str) -> str:
    """Session file belonging to a vault"""
    return os.path.abspath(vault_path) + ".session"


def start_session(crypto: Crypto, vault_path: str, timeout_minutes: float = DEFAULT_TIMEOUT_MINUTES) -> str:
    """
    Start an agent holding the vault key, replacing any running session.

    Args:
        crypto: Crypto instance holding the unlocked vault's key
        vault_path: Path of the vault
        timeout_minutes: Session ends after this many minutes without use

    Returns:
        The session token to export as VAULTKEY_SESSION

    Raises:
        OSError: The agent could not be started
    """
    end_session(vault_path)
    token = secrets.token_bytes(32)
    agent = spawn_helper("_session-agent", capture_output=True)
    agent.stdin.write(json.dumps({
        "vault": os.path.abspath(vault_path),
        "token": token.hex(),
        "key": base64.b64encode(crypto.key).decode(),
        "salt": base64.b64encode(crypto.salt).decode(),
        "kdf_params": crypto.kdf_params,
        "timeout": timeout_minutes * 60,
    }).encode("utf-8"))
    agent.stdin.close()

    # The agent reports once it is listening and has written the session file
    ready = agent.stdout.readline()
    agent.stdout.close()
    if ready.strip() != b"ready":
        raise OSError("Could not start the session agent")
    return base64.urlsafe_b64encode(token).decode()


def resume_session(vault_path: str, token: Optional[str] = None) -> Optional[Crypto]:
    """
    Return a Crypto holding the vault key if a valid session exists, else None.

    Each successful use extends the session by its timeout.
    """
    reply = _request(vault_path, token, b"key")
    if reply is None:
        return None
    crypto = Crypto()
    crypto.key = base64.b64decode(reply["key"])
    crypto.salt = base64.b64decode(reply["salt"])
    crypto.kdf_params = reply["kdf_params"]
    return crypto


def session_expiry(vault_path: str, token: Optional[str] = None) -> Optional[float]:
    """Expiry time of the active session (without extending it), or None"""
    reply = _request(vault_path, token, b"status")
    return reply["expires"] if reply else None


def end_session(vault_path: str) -> bool:
    """End the session by removing its file; the agent notices and exits. Returns True if one existed."""
    try:
        _retry(os.remove, session_file(vault_path))
        return True
    except FileNotFoundError:
        return False


def _request(vault_path: str, token: Optional[str], request: bytes) -> Optional[dict]:
    """Send one request to the vault's agent, or return None if there is no usable session"""
    token = token if token is not None else os.environ.get(SESSION_ENV)
    if not token:
        return None
    try:
        with open(session_file(vault_path), encoding="utf-8") as f:
            address = json.load(f)
        authkey = base64.urlsafe_b64decode(token.encode())
        with Client(address["address"], address["family"], authkey=authkey) as conn:
            conn.send_bytes(request)
            reply = json.loads(conn.recv_bytes().decode("utf-8"))
    except (OSError, EOFError, AuthenticationError, ValueError, KeyError, TypeError, binascii.Error):
        return None  # No session, an agent that has exited, or a token from another session
    if reply.get("vault") != os.path.abspath(vault_path):
        return None
    return reply


# --- The agent process ------------------------------------------------------------

def run_agent() -> None:
    """Agent entry point (`vk _session-agent`): read the job from stdin and serve the key"""
    job = json.loads(sys.stdin.read())
    authkey = bytes.fromhex(job.pop("token"))
    path = session_file(job["vault"])
    state = {"expires": time.time() + job["timeout"]}
    lock = threading.Lock()

    if os.name == "nt":
        family, directory = "AF_PIPE", None
        address = r"\\.\pipe\vaultkey-" + secrets.token_hex(16)
    else:
        family, directory = "AF_UNIX", tempfile.mkdtemp(prefix="vaultkey-")  # 0700
        address = os.path.join(directory, "agent.sock")
    # No authkey here: each connection is authenticated in its own thread, so
    # a client that stalls mid-handshake can't block the others
    listener = Listener(address, family)
    marker = json.dumps({"address": address, "family": family, "pid": os.getpid()})
    _write_private(path, marker)

    def stop() -> None:
        try:
            with open(path, encoding="utf-8") as f:
                ours = f.read() == marker
            if ours:
                _retry(os.remove, path)
        except OSError:
            pass
        if directory:
            shutil.rmtree(directory, ignore_errors=True)
        os._exit(0)

    def watch() -> None:
        # Exit once the session is idle too long, or `vk lock` (or a new
        # `vk unlock`) has removed or replaced our session file
        while True:
            time.sleep(_WATCH_INTERVAL)
            try:
                with open(path, encoding="utf-8") as f:
                    current = f.read()
            except FileNotFoundError:
                current = None
            except OSError:
                continue  # Briefly locked by another process (Windows); look again
            with lock:
                if current != marker or time.time() > state["expires"]:
                    stop()

    def serve(conn) -> None:
        try:
            deliver_challenge(conn, authkey)
            answer_challenge(conn, authkey)
            request = conn.recv_bytes(64)
            with lock:
                if time.time() > state["expires"]:
                    stop()
                if request == b"key":
                    state["expires"] = time.time() + job["timeout"]
                    reply = dict(job, expires=state["expires"])
                elif request == b"status":
                    reply = {"vault": job["vault"], "expires": state["expires"]}
                else:
                    return
            conn.send_bytes(json.dumps(reply).encode("utf-8"))
        except (OSError, EOFError, AuthenticationError):
            pass
        finally:
            conn.close()

    threading.Thread(target=watch, daemon=True).start()
    sys.stdout.write("ready\n")
    sys.stdout.flush()
    sys.stdout.close()

    while True:
        try:
            conn = listener.accept()
        except OSError:
            continue
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


def _write_private(path: str, text: str) -> None:
    """Write a small owner-only (0600) file"""
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd, "w", encoding="utf-8") as f:
        f.write(text)
    _retry(os.replace, path + ".tmp", path)


def _retry(operation, *args):
    """
    Run a file operation, retrying briefly on Windows, where removing or
    replacing a file fails while another process (the agent checking its
    session file, or a command reading it) has it open.
    """
    for attempt in range(40):
        try:
            return operation(*args)
        except PermissionError:
            if os.name != "nt" or attempt == 39:
                raise
            time.sleep(0.05)
