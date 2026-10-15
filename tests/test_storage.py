import os
import stat

import pytest

from vaultkey.storage import CURRENT_VERSION, Storage


def test_save_and_load_roundtrip(tmp_path):
    storage = Storage(str(tmp_path / "sub" / "vault.bin"))
    storage.save(b"payload:with:colons")
    assert storage.load() == (CURRENT_VERSION, b"payload:with:colons")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_saved_file_is_owner_only(tmp_path):
    path = tmp_path / "vault.bin"
    Storage(str(path)).save(b"x")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_save_leaves_no_temp_files(tmp_path):
    storage = Storage(str(tmp_path / "vault.bin"))
    storage.save(b"one")
    storage.save(b"two")
    assert os.listdir(tmp_path) == ["vault.bin"]


def test_failed_write_keeps_previous_file(tmp_path, monkeypatch):
    storage = Storage(str(tmp_path / "vault.bin"))
    storage.save(b"original")

    def crash(*args):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(OSError):
        storage.save(b"new")

    assert storage.load() == (CURRENT_VERSION, b"original")
    assert os.listdir(tmp_path) == ["vault.bin"]


def test_legacy_file_without_header_is_version_1(tmp_path):
    path = tmp_path / "vault.bin"
    path.write_bytes(b"gAAAAAtoken")
    assert Storage(str(path)).load() == (1, b"gAAAAAtoken")
