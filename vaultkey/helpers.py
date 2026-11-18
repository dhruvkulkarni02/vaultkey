"""
helpers.py - Start VaultKey's detached background helpers (clipboard clearer, session agent)
"""
import os
import subprocess
import sys
import tempfile

# Package root, so the helper imports this VaultKey even when it isn't installed
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# `python -m` and `python -c` put the working directory first on sys.path, so a
# stray pyperclip.py or click.py there would run inside the helper. Drop it.
_BOOTSTRAP = (
    "import os, sys\n"
    "if sys.path and sys.path[0] in ('', os.getcwd()): del sys.path[0]\n"
    "if {root!r} not in sys.path: sys.path.append({root!r})\n"
    "from vaultkey.cli import cli\n"
    "cli([{command!r}])\n"
)


def helper_command(command: str) -> list:
    """argv that runs the hidden CLI command `command` in a fresh process"""
    if getattr(sys, "frozen", False):
        # PyInstaller build: the executable is the VaultKey CLI itself
        return [sys.executable, command]
    return [sys.executable, "-c", _BOOTSTRAP.format(root=_ROOT, command=command)]


def spawn_helper(command: str, capture_output: bool = False) -> subprocess.Popen:
    """
    Start `command` detached from this process (it outlives it), with a pipe
    for its job on stdin and, if capture_output, one for its stdout.
    """
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    return subprocess.Popen(
        helper_command(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # Not the user's directory: the helper shouldn't keep it busy
        cwd=tempfile.gettempdir(),
        **kwargs
    )
