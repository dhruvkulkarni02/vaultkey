import json
import os
import stat

import pytest

from vaultkey.portability import VaultExporter, VaultImporter

PASSWORDS = {
    "github.com": {"username": "octocat", "password": "=cmd|' /C calc'!A0", "notes": "n,1",
                   "created": "2024-01-01", "modified": "2024-01-02"},
    "gitlab.com": {"username": "me", "password": "pa\"ss", "notes": "",
                   "created": "", "modified": ""},
}


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_generic_csv_maps_columns_by_header_name(tmp_path):
    # Chrome export column order: name,url,username,password
    path = write(tmp_path, "chrome.csv",
                 "name,url,username,password\nGitHub,https://github.com,octocat,s3cret\n")
    result = VaultImporter().import_file(path, "csv")
    assert result["GitHub"]["username"] == "octocat"
    assert result["GitHub"]["password"] == "s3cret"


def test_generic_csv_keepassxc_header(tmp_path):
    path = write(tmp_path, "kp.csv",
                 '"Group","Title","Username","Password","URL","Notes"\n'
                 '"Root","Mail","alice","pw1","https://mail","note"\n'
                 '"Root","Bank","bob","pw2","https://bank",""\n')
    result = VaultImporter().import_file(path, "csv")
    assert set(result) == {"Mail", "Bank"}
    assert result["Mail"] == {**result["Mail"], "username": "alice", "password": "pw1", "notes": "note"}


def test_generic_csv_without_header_is_positional(tmp_path):
    path = write(tmp_path, "plain.csv", "example.com,user,pw,a note\nother.org,u2,pw2\n")
    result = VaultImporter().import_file(path, "csv")
    assert result["example.com"]["password"] == "pw"
    assert result["example.com"]["notes"] == "a note"
    assert result["other.org"]["username"] == "u2"


def test_generic_csv_header_without_password_column_is_refused(tmp_path):
    path = write(tmp_path, "bad.csv", "site,username,secret\na,b,c\n")
    with pytest.raises(ValueError, match="password"):
        VaultImporter().import_file(path, "csv")


def test_csv_export_roundtrips_tricky_values(tmp_path):
    out = str(tmp_path / "export.csv")
    VaultExporter().export_passwords(PASSWORDS, "csv", out)
    result = VaultImporter().import_file(out, "csv")
    for site, entry in PASSWORDS.items():
        assert result[site]["password"] == entry["password"]
        assert result[site]["notes"] == entry["notes"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_export_file_is_owner_only(tmp_path):
    out = str(tmp_path / "export.json")
    VaultExporter().export_passwords(PASSWORDS, "json", out)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600


def test_json_export_import_roundtrip(tmp_path):
    out = str(tmp_path / "export.json")
    VaultExporter().export_passwords(PASSWORDS, "json", out)
    result = VaultImporter().import_file(out, "json")
    assert result["gitlab.com"]["password"] == 'pa"ss'


def test_encrypted_export_import_roundtrip_without_temp_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = VaultExporter().export_passwords(PASSWORDS, "vaultkey", master_password="export-pw")
    path = write(tmp_path, "export.vk.json", data)

    assert os.listdir(tmp_path) == ["export.vk.json"]  # no salt files left in the CWD
    assert VaultImporter().import_file(path, "vaultkey", "export-pw") == PASSWORDS
    with pytest.raises(ValueError):
        VaultImporter().import_file(path, "vaultkey", "wrong")


def test_legacy_encrypted_export_still_imports(tmp_path):
    import base64
    from cryptography.fernet import Fernet
    from conftest import legacy_fernet_key

    salt = os.urandom(32)
    token = Fernet(legacy_fernet_key("export-pw", salt)).encrypt(
        json.dumps({"passwords": PASSWORDS}).encode())
    path = write(tmp_path, "old.json", json.dumps({
        "format": "vaultkey_encrypted", "version": "1.0",
        "salt": base64.b64encode(salt).decode(), "encrypted_data": base64.b64encode(token).decode(),
    }))
    assert VaultImporter().import_file(path, "vaultkey", "export-pw") == PASSWORDS


def test_import_keeps_multiple_accounts_for_one_site(tmp_path):
    path = write(tmp_path, "lp.csv",
                 "url,username,password,totp,extra,name,grouping,fav\n"
                 "https://mail.google.com,alice,pw1,,,Gmail,,0\n"
                 "https://mail.google.com,bob,pw2,,,Gmail,,0\n"
                 "https://mail.google.com,bob,pw3,,,Gmail,,0\n"
                 "https://mail.google.com,alice,pw1,,,Gmail,,0\n")
    result = VaultImporter().import_file(path, "lastpass")
    assert {site: e["password"] for site, e in result.items()} == {
        "Gmail": "pw1",
        "Gmail (bob)": "pw2",
        "Gmail (bob) #2": "pw3",
    }
