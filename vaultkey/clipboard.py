"""
clipboard.py - Copy secrets to the clipboard and clear them again later

Clearing is done by a small detached helper process, so it still happens after
a one-shot command like `vk cp` has exited.
"""
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time


def copy_with_autoclear(text: str, timeout: int = 30) -> bool:
    """
    Copy text to the clipboard and clear it after `timeout` seconds.

    The previous clipboard content is restored, but only if the clipboard still
    holds `text` by then - anything copied in the meantime is left alone.

    Returns:
        False if clipboard support (pyperclip) is unavailable, True otherwise
    """
    try:
        import pyperclip
    except ImportError:
        return False

    try:
        previous = pyperclip.paste()
    except Exception:
        previous = ""

    pyperclip.copy(text)
    if timeout > 0:
        _start_clearer(text, previous, timeout)
    return True


def _fingerprint(key: bytes, text: str) -> str:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


def _start_clearer(text: str, previous: str, timeout: int) -> None:
    """Start a detached process that runs run_clearer() after this one exits"""
    # The helper only gets a keyed fingerprint of the secret (through a pipe,
    # never argv), which is enough to check whether the clipboard still holds it.
    key = secrets.token_bytes(32)
    payload = json.dumps({
        "timeout": timeout,
        "key": key.hex(),
        "fingerprint": _fingerprint(key, text),
        "restore": previous,
    })

    if getattr(sys, "frozen", False):
        # PyInstaller build: the executable is the VaultKey CLI itself
        command = [sys.executable, "_clear-clipboard"]
    else:
        command = [sys.executable, "-m", "vaultkey", "_clear-clipboard"]

    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **kwargs
    )
    process.stdin.write(payload.encode("utf-8"))
    process.stdin.close()


def run_clearer() -> None:
    """Helper process entry point: read the job from stdin, wait, then clear"""
    job = json.loads(sys.stdin.read())
    time.sleep(job["timeout"])

    import pyperclip
    current = pyperclip.paste()
    if hmac.compare_digest(_fingerprint(bytes.fromhex(job["key"]), current), job["fingerprint"]):
        pyperclip.copy(job["restore"] or "")
