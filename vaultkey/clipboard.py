"""
clipboard.py - Copy secrets to the clipboard and clear them again later

Clearing is done by a small detached helper process, so it still happens after
a one-shot command like `vk cp` has exited.

On macOS and Windows, copied secrets are also marked so that clipboard history,
clipboard managers and syncing to other devices leave them out.
"""
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import secrets
import sys
import time

from .helpers import spawn_helper


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

    if not copy_concealed(text):
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

    process = spawn_helper("_clear-clipboard")
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


def copy_concealed(text: str) -> bool:
    """
    Copy text marked as a secret that clipboard history and syncing should skip.

    Returns:
        False if this platform isn't supported or the native clipboard failed;
        the caller then copies it the ordinary way
    """
    try:
        if sys.platform == "darwin":
            return _copy_concealed_macos(text)
        if sys.platform == "win32":
            return _copy_concealed_windows(text)
    except Exception:
        pass
    return False


def _copy_concealed_macos(text: str) -> bool:
    """NSPasteboard: this Mac only (no Universal Clipboard), and the
    org.nspasteboard.ConcealedType marker that clipboard managers honour"""
    objc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("objc"))
    ctypes.cdll.LoadLibrary(ctypes.util.find_library("AppKit"))
    objc.objc_getClass.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = [ctypes.c_char_p]
    objc.sel_registerName.restype = ctypes.c_void_p
    objc.sel_registerName.argtypes = [ctypes.c_char_p]
    objc.objc_autoreleasePoolPush.restype = ctypes.c_void_p
    objc.objc_autoreleasePoolPop.argtypes = [ctypes.c_void_p]
    msg_send = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value

    def send(restype, receiver, selector, *args):
        # objc_msgSend has to be called through a prototype matching each method
        prototype = ctypes.CFUNCTYPE(restype, ctypes.c_void_p, ctypes.c_void_p, *(type(a) for a in args))
        return prototype(msg_send)(receiver, objc.sel_registerName(selector), *args)

    def nsstring(value: str):
        return ctypes.c_void_p(send(ctypes.c_void_p, objc.objc_getClass(b"NSString"),
                                    b"stringWithUTF8String:", ctypes.c_char_p(value.encode("utf-8"))))

    pool = objc.objc_autoreleasePoolPush()
    try:
        board = ctypes.c_void_p(send(ctypes.c_void_p, objc.objc_getClass(b"NSPasteboard"), b"generalPasteboard"))
        prepare = ctypes.c_void_p(objc.sel_registerName(b"prepareForNewContentsWithOptions:"))
        if send(ctypes.c_bool, board, b"respondsToSelector:", prepare):  # macOS 12+
            send(ctypes.c_long, board, b"prepareForNewContentsWithOptions:", ctypes.c_ulong(1))  # CurrentHostOnly
        else:
            send(ctypes.c_long, board, b"clearContents")
        string = nsstring(text)
        return (send(ctypes.c_bool, board, b"setString:forType:", string, nsstring("public.utf8-plain-text"))
                and send(ctypes.c_bool, board, b"setString:forType:", nsstring(""),
                         nsstring("org.nspasteboard.ConcealedType")))
    finally:
        objc.objc_autoreleasePoolPop(pool)


def _copy_concealed_windows(text: str) -> bool:
    """Win32 clipboard, with the formats that keep it out of clipboard history
    (Win+V), cloud clipboard sync and clipboard monitors"""
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]

    def put(clipboard_format: int, data: bytes) -> None:
        handle = kernel32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        pointer = kernel32.GlobalLock(handle)
        ctypes.memmove(pointer, data, len(data))
        kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(clipboard_format, handle):
            kernel32.GlobalFree(handle)  # Still ours: only a successful call hands it over
            raise ctypes.WinError(ctypes.get_last_error())

    for _ in range(20):  # Another program may have the clipboard open for a moment
        if user32.OpenClipboard(None):
            break
        time.sleep(0.01)
    else:
        return False
    try:
        user32.EmptyClipboard()
        put(13, (text + "\0").encode("utf-16-le"))  # CF_UNICODETEXT
        no = (0).to_bytes(4, "little")
        put(user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing"), no)
        put(user32.RegisterClipboardFormatW("CanIncludeInClipboardHistory"), no)
        put(user32.RegisterClipboardFormatW("CanUploadToCloudClipboard"), no)
        return True
    finally:
        user32.CloseClipboard()
