import json
import subprocess
import sys

import pytest

from vaultkey import clipboard

TEXT = "vk-test sécret ✓"


@pytest.fixture
def real_clipboard():
    """The system clipboard, restored afterwards"""
    if sys.platform not in ("darwin", "win32"):
        pytest.skip("concealed copying is only implemented for macOS and Windows")
    pyperclip = pytest.importorskip("pyperclip")
    try:
        previous = pyperclip.paste()
    except Exception:
        pytest.skip("no clipboard available")
    yield pyperclip
    pyperclip.copy(previous)


def test_concealed_copy_pastes_normally_and_is_marked_secret(real_clipboard):
    if not clipboard.copy_concealed(TEXT):
        pytest.skip("the native clipboard isn't available here")
    assert real_clipboard.paste() == TEXT

    if sys.platform == "darwin":
        script = ('ObjC.import("AppKit"); '
                  'JSON.stringify(ObjC.deepUnwrap($.NSPasteboard.generalPasteboard.types))')
        types = json.loads(subprocess.run(["osascript", "-l", "JavaScript", "-e", script],
                                          capture_output=True, text=True, check=True).stdout)
        assert "org.nspasteboard.ConcealedType" in types
    else:
        import ctypes
        user32 = ctypes.WinDLL("user32")
        user32.RegisterClipboardFormatW.restype = ctypes.c_uint
        for name in ("ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory"):
            assert user32.IsClipboardFormatAvailable(user32.RegisterClipboardFormatW(name))


def test_copy_falls_back_to_pyperclip(monkeypatch):
    copied = []
    monkeypatch.setitem(sys.modules, "pyperclip", type(sys)("pyperclip"))
    sys.modules["pyperclip"].paste = lambda: "previous"
    sys.modules["pyperclip"].copy = copied.append
    monkeypatch.setattr(clipboard, "copy_concealed", lambda text: False)
    monkeypatch.setattr(clipboard, "_start_clearer", lambda *args: None)
    assert clipboard.copy_with_autoclear("secret", 30)
    assert copied == ["secret"]
