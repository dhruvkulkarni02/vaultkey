import importlib
import io
import json
import sys
import types

import pytest
from click.testing import CliRunner

from vaultkey import clipboard

# `vaultkey.cli` the attribute is the click group; we need the module
cli_module = importlib.import_module("vaultkey.cli")

MASTER = "correct horse battery staple"


@pytest.fixture
def run(monkeypatch, vault_path):
    """Run a CLI command against a temporary vault, answering getpass prompts in order"""
    monkeypatch.setattr(cli_module, "DEFAULT_VAULT", vault_path)

    def invoke(args, secrets=(), input=None, vault=None):
        if vault:
            monkeypatch.setattr(cli_module, "DEFAULT_VAULT", vault)
        monkeypatch.setattr(cli_module, "pm", None)
        answers = iter(secrets)
        monkeypatch.setattr(cli_module.getpass, "getpass", lambda prompt="": next(answers))
        return CliRunner().invoke(cli_module.cli, args, input=input)

    return invoke


@pytest.fixture
def fake_clipboard(monkeypatch):
    board = {"value": "previous"}
    module = types.SimpleNamespace(
        copy=lambda text: board.__setitem__("value", text),
        paste=lambda: board["value"],
    )
    monkeypatch.setitem(sys.modules, "pyperclip", module)
    started = []
    monkeypatch.setattr(clipboard, "_start_clearer",
                        lambda text, previous, timeout: started.append((text, previous, timeout)))
    return board, started


def init_vault(run):
    result = run(["init"], secrets=[MASTER, MASTER])
    assert result.exit_code == 0, result.output


def add_entry(run, site="github.com", password="gh-secret"):
    result = run(["add", "-s", site, "-u", "octocat"], secrets=[MASTER, password, password])
    assert result.exit_code == 0, result.output


def test_init_add_get(run):
    init_vault(run)
    add_entry(run)
    result = run(["get", "-s", "github.com", "--show"], secrets=[MASTER])
    assert result.exit_code == 0
    assert "gh-secret" in result.output


def test_wrong_master_password_exits_nonzero(run):
    init_vault(run)
    result = run(["list"], secrets=["wrong"])
    assert result.exit_code == 1
    assert "Invalid master password" in result.output


def test_get_declined_partial_match_does_not_crash(run):
    init_vault(run)
    add_entry(run)
    result = run(["get", "-s", "git"], secrets=[MASTER], input="n\n")
    assert result.exit_code == 0
    assert "Error" not in result.output


def test_cp_copies_and_schedules_clearing(run, fake_clipboard):
    board, started = fake_clipboard
    init_vault(run)
    add_entry(run)
    result = run(["cp", "github.com", "-t", "15"], secrets=[MASTER])
    assert result.exit_code == 0, result.output
    assert board["value"] == "gh-secret"
    assert started == [("gh-secret", "previous", 15)]


def test_backup_then_restore_onto_machine_without_vault(run, tmp_path):
    init_vault(run)
    add_entry(run)
    backup = str(tmp_path / "vault.vkbak")
    result = run(["backup", "-o", backup], secrets=[MASTER], input="y\n")
    assert result.exit_code == 0, result.output

    new_vault = str(tmp_path / "new-home" / "passwords.encrypted")
    result = run(["restore", backup], secrets=[MASTER, "new-master", "new-master"], vault=new_vault)
    assert result.exit_code == 0, result.output
    assert "restored" in result.output

    result = run(["get", "-s", "github.com", "--show"], secrets=["new-master"], vault=new_vault)
    assert "gh-secret" in result.output


def test_restore_with_wrong_backup_password_fails_cleanly(run, tmp_path):
    init_vault(run)
    add_entry(run)
    backup = str(tmp_path / "vault.vkbak")
    run(["backup", "-o", backup], secrets=[MASTER], input="y\n")

    result = run(["restore", backup], secrets=["wrong", MASTER], input="y\n")
    assert result.exit_code == 1
    assert "Restore failed" in result.output


def test_import_csv_by_header(run, tmp_path):
    init_vault(run)
    csv_file = tmp_path / "chrome.csv"
    csv_file.write_text("name,url,username,password\nGitHub,https://github.com,octocat,s3cret\n")
    result = run(["import-passwords", str(csv_file)], secrets=[MASTER])
    assert result.exit_code == 0, result.output
    result = run(["get", "-s", "GitHub", "--show"], secrets=[MASTER])
    assert "s3cret" in result.output


def test_clearer_restores_previous_content_only_if_unchanged(monkeypatch):
    board = {"value": "secret"}
    monkeypatch.setitem(sys.modules, "pyperclip", types.SimpleNamespace(
        copy=lambda text: board.__setitem__("value", text),
        paste=lambda: board["value"],
    ))

    captured = {}

    class FakePopen:
        def __init__(self, command, **kwargs):
            captured["command"] = command
            self.stdin = io.BytesIO()
            self.stdin.close = lambda: captured.__setitem__("payload", self.stdin.getvalue())

    monkeypatch.setattr(clipboard.subprocess, "Popen", FakePopen)
    clipboard._start_clearer("secret", "previous", 0)

    assert captured["command"][-1] == "_clear-clipboard"
    payload = json.loads(captured["payload"])
    assert "secret" not in captured["payload"].decode()  # only a keyed fingerprint is passed

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    clipboard.run_clearer()
    assert board["value"] == "previous"

    board["value"] = "something the user copied later"
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    clipboard.run_clearer()
    assert board["value"] == "something the user copied later"


def test_passwd_changes_master_password(run):
    init_vault(run)
    add_entry(run)
    result = run(["passwd"], secrets=[MASTER, "new-master", "new-master"])
    assert result.exit_code == 0, result.output
    assert run(["list"], secrets=[MASTER]).exit_code == 1
    assert "gh-secret" in run(["get", "-s", "github.com", "--show"], secrets=["new-master"]).output


def test_passwd_with_wrong_current_password_fails(run):
    init_vault(run)
    result = run(["passwd"], secrets=["wrong"])
    assert result.exit_code == 1


def test_search_without_query_filters_by_type(run):
    init_vault(run)
    add_entry(run, "weak.com", "password")
    add_entry(run, "strong.com", "Xq7#vB2!mK9$pL4@zR8&")
    result = run(["search", "--type", "weak"], secrets=[MASTER])
    assert result.exit_code == 0, result.output
    assert "weak.com" in result.output and "strong.com" not in result.output


def test_breaches_offline_is_not_reported_clean(run, monkeypatch):
    init_vault(run)
    add_entry(run)
    monkeypatch.setattr(cli_module.BreachChecker, "check_password", lambda self, pw: {
        "error": True, "message": "offline", "found": False, "count": 0})
    result = run(["breaches"], secrets=[MASTER])
    assert result.exit_code == 1
    assert "Great!" not in result.output
    assert "internet connection" in result.output


def test_version_shows_package_version(run):
    from vaultkey import __version__
    result = run(["version"])
    assert __version__ in result.output and "Your Name" not in result.output
