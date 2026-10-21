import importlib
import io
import json
import os
import sys
import types

import pytest
from click.testing import CliRunner

from vaultkey import clipboard

# `vaultkey.cli` the attribute is the click group; we need the module
cli_module = importlib.import_module("vaultkey.cli")

MASTER = "correct horse battery staple"
NEW_MASTER = "purple elephant marching quietly"


@pytest.fixture
def run(monkeypatch, vault_path):
    """Run a CLI command against a temporary vault, answering getpass prompts in order"""
    monkeypatch.setattr(cli_module, "DEFAULT_VAULT", vault_path)

    def invoke(args, secrets=(), input=None, vault=None, session=None):
        if vault:
            monkeypatch.setattr(cli_module, "DEFAULT_VAULT", vault)
        monkeypatch.setattr(cli_module, "pm", None)
        answers = iter(secrets)
        monkeypatch.setattr(cli_module.getpass, "getpass", lambda prompt="": next(answers))
        return CliRunner().invoke(cli_module.cli, args, input=input, env={"VAULTKEY_SESSION": session})

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


def add_entry(run, site="github.com", password="gh-secret", username="octocat"):
    result = run(["add", "-s", site, "-u", username], secrets=[MASTER, password, password])
    assert result.exit_code == 0, result.output


def start_session(run):
    result = run(["unlock", "--shell", "posix"], secrets=[MASTER])
    assert result.exit_code == 0, result.output
    line = next(l for l in result.output.splitlines() if l.startswith("export VAULTKEY_SESSION="))
    return line.split("=", 1)[1].strip('"')


# --- basics ------------------------------------------------------------------

def test_init_add_get(run):
    init_vault(run)
    add_entry(run)
    result = run(["get", "-s", "github.com", "--show"], secrets=[MASTER])
    assert result.exit_code == 0
    assert "gh-secret" in result.output
    assert "octocat" in result.output


def test_get_hides_password_by_default(run):
    init_vault(run)
    add_entry(run)
    result = run(["get", "-s", "github.com"], secrets=[MASTER])
    assert "gh-secret" not in result.output


def test_init_warns_about_weak_master_password(run):
    result = run(["init"], secrets=["short", "short"], input="n\n")
    assert result.exit_code == 1
    assert "weak" in result.output
    result = run(["init"], secrets=["short", "short"], input="y\n")
    assert result.exit_code == 0, result.output


def test_wrong_master_password_exits_nonzero(run):
    init_vault(run)
    result = run(["list"], secrets=["wrong"])
    assert result.exit_code == 1
    assert "Invalid master password" in result.output


def test_commands_without_a_vault_explain_init(run):
    result = run(["list"])
    assert result.exit_code == 1
    assert "vk init" in result.output


def test_user_text_is_not_treated_as_markup(run):
    init_vault(run)
    add_entry(run, site="[bold]weird[/bold] site", username="[red]me[/red]")
    result = run(["list"], secrets=[MASTER])
    assert "[bold]weird[/bold] site" in result.output
    assert "[red]me[/red]" in result.output


# --- finding entries ----------------------------------------------------------

def test_single_partial_match_is_used(run):
    init_vault(run)
    add_entry(run)
    result = run(["get", "-s", "git", "--show"], secrets=[MASTER])
    assert result.exit_code == 0
    assert "Using github.com" in result.output and "gh-secret" in result.output


def test_ambiguous_match_lists_candidates(run):
    init_vault(run)
    add_entry(run, "github.com")
    add_entry(run, "gitlab.com")
    result = run(["get", "-s", "git"], secrets=[MASTER])
    assert result.exit_code == 1
    assert "github.com" in result.output and "gitlab.com" in result.output


def test_no_match_exits_nonzero(run):
    init_vault(run)
    result = run(["get", "-s", "nothing"], secrets=[MASTER])
    assert result.exit_code == 1


def test_search_without_query_filters_by_type(run):
    init_vault(run)
    add_entry(run, "weak.com", "password")
    add_entry(run, "strong.com", "Xq7#vB2!mK9$pL4@zR8&")
    result = run(["search", "--type", "weak"], secrets=[MASTER])
    assert result.exit_code == 0, result.output
    assert "weak.com" in result.output and "strong.com" not in result.output


# --- JSON output ----------------------------------------------------------------

def test_json_output_is_clean_and_parseable(run):
    init_vault(run)
    add_entry(run)
    add_entry(run, "gitlab.com", "other-secret")

    runner_result = run(["list", "--json"], secrets=[MASTER])
    stdout = runner_result.stdout if hasattr(runner_result, "stdout") else runner_result.output
    entries = json.loads(stdout[stdout.index("["):])
    assert [e["site"] for e in entries] == ["github.com", "gitlab.com"]
    assert all("password" not in e for e in entries)

    result = run(["get", "-s", "github.com", "--json"], secrets=[MASTER])
    entry = json.loads(result.output[result.output.index("{"):])
    assert entry["password"] == "gh-secret"


def test_generate_json(run):
    result = run(["generate", "-c", "3", "-l", "12", "--json"])
    passwords = json.loads(result.output)
    assert len(passwords) == 3 and all(len(p) == 12 for p in passwords)


def test_audit_json_reports_reuse(run):
    init_vault(run)
    add_entry(run, "a.com", "same-password-1")
    add_entry(run, "b.com", "same-password-1")
    result = run(["audit", "--json"], secrets=[MASTER])
    report = json.loads(result.output[result.output.index("{"):])
    assert report["summary"]["reused"] == 2
    assert {e["site"]: e["reused_with"] for e in report["entries"]} == {"a.com": ["b.com"], "b.com": ["a.com"]}


# --- editing --------------------------------------------------------------------

def test_edit_generates_new_password_and_keeps_history(run):
    init_vault(run)
    add_entry(run)
    result = run(["edit", "github.com", "-g", "-l", "24"], secrets=[MASTER])
    assert result.exit_code == 0, result.output

    entry = json.loads(_json(run(["get", "-s", "github.com", "--json"], secrets=[MASTER])))
    assert entry["password"] != "gh-secret" and len(entry["password"]) == 24

    result = run(["history", "github.com", "--show"], secrets=[MASTER])
    assert "gh-secret" in result.output


def test_edit_username_and_notes(run):
    init_vault(run)
    add_entry(run)
    result = run(["edit", "github.com", "-u", "newname", "-n", "work account"], secrets=[MASTER])
    assert result.exit_code == 0, result.output
    entry = json.loads(_json(run(["get", "-s", "github.com", "--json"], secrets=[MASTER])))
    assert entry["username"] == "newname" and entry["notes"] == "work account"
    assert entry["password"] == "gh-secret"


def test_rename(run):
    init_vault(run)
    add_entry(run)
    add_entry(run, "gitlab.com")
    assert run(["rename", "github.com", "GitHub"], secrets=[MASTER]).exit_code == 0
    assert run(["rename", "GitHub", "gitlab.com"], secrets=[MASTER]).exit_code == 1  # name taken
    result = run(["list", "--json"], secrets=[MASTER])
    assert [e["site"] for e in json.loads(_json(result))] == ["GitHub", "gitlab.com"]


def test_history_clear(run):
    init_vault(run)
    add_entry(run)
    run(["edit", "github.com", "-g"], secrets=[MASTER])
    result = run(["history", "github.com", "--clear"], secrets=[MASTER], input="y\n")
    assert "Deleted 1" in result.output
    assert "no previous passwords" in run(["history", "github.com"], secrets=[MASTER]).output


def test_delete_needs_exact_name(run):
    init_vault(run)
    add_entry(run)
    assert run(["delete", "git", "-f"], secrets=[MASTER]).exit_code == 1
    assert run(["delete", "github.com", "-f"], secrets=[MASTER]).exit_code == 0


def test_add_existing_asks_before_replacing(run):
    init_vault(run)
    add_entry(run)
    result = run(["add", "-s", "github.com", "-u", "x"], secrets=[MASTER], input="n\n")
    assert result.exit_code == 0
    assert "gh-secret" in run(["get", "-s", "github.com", "--show"], secrets=[MASTER]).output


# --- sessions -------------------------------------------------------------------

def test_unlock_session_skips_password_prompt(run):
    init_vault(run)
    add_entry(run)
    token = start_session(run)

    result = run(["get", "-s", "github.com", "--show"], session=token)  # no secrets: must not prompt
    assert result.exit_code == 0, result.output
    assert "gh-secret" in result.output
    assert "unlocked" in run(["status"], session=token).output

    assert run(["lock"]).exit_code == 0
    result = run(["get", "-s", "github.com"], secrets=["wrong"], session=token)
    assert result.exit_code == 1  # prompted again after lock


def test_wrong_token_is_ignored(run):
    init_vault(run)
    start_session(run)
    result = run(["list"], secrets=[MASTER], session="bm90LWEtdG9rZW4=")
    assert result.exit_code == 0


def test_passwd_ends_session(run):
    init_vault(run)
    add_entry(run)
    token = start_session(run)
    result = run(["passwd"], secrets=[MASTER, NEW_MASTER, NEW_MASTER])
    assert result.exit_code == 0, result.output
    result = run(["list"], secrets=[NEW_MASTER], session=token)
    assert result.exit_code == 0  # had to use the new password


def test_shell_export_syntax(run):
    init_vault(run)
    assert run(["unlock", "--shell", "fish"], secrets=[MASTER]).output.startswith("set -gx VAULTKEY_SESSION ")
    assert run(["unlock", "--shell", "powershell"], secrets=[MASTER]).output.startswith("$env:VAULTKEY_SESSION=")


def test_completion_script(run):
    result = run(["completion", "zsh"])
    assert result.exit_code == 0 and "_VK_COMPLETE" in result.output


def test_site_completion_uses_session(run, monkeypatch, vault_path):
    init_vault(run)
    add_entry(run, "github.com")
    add_entry(run, "gitlab.com")
    add_entry(run, "example.org")
    token = start_session(run)

    monkeypatch.setenv("VAULTKEY_SESSION", token)
    names = [item.value for item in cli_module.complete_site(None, None, "git")]
    assert names == ["github.com", "gitlab.com"]

    monkeypatch.delenv("VAULTKEY_SESSION")
    assert cli_module.complete_site(None, None, "git") == []


# --- clipboard, backup, import, misc ---------------------------------------------

def test_cp_copies_and_schedules_clearing(run, fake_clipboard):
    board, started = fake_clipboard
    init_vault(run)
    add_entry(run)
    result = run(["cp", "github.com", "-t", "15"], secrets=[MASTER])
    assert result.exit_code == 0, result.output
    assert board["value"] == "gh-secret"
    assert started == [("gh-secret", "previous", 15)]

    run(["cp", "github.com", "--username"], secrets=[MASTER])
    assert board["value"] == "octocat"


def test_backup_then_restore_onto_machine_without_vault(run, tmp_path):
    init_vault(run)
    add_entry(run)
    backup = str(tmp_path / "vault.vkbak")
    result = run(["backup", "-o", backup], secrets=[MASTER], input="y\n")
    assert result.exit_code == 0, result.output

    new_vault = str(tmp_path / "new-home" / "passwords.encrypted")
    result = run(["restore", backup], secrets=[MASTER, NEW_MASTER, NEW_MASTER], vault=new_vault)
    assert result.exit_code == 0, result.output
    assert "restored" in result.output

    result = run(["get", "-s", "github.com", "--show"], secrets=[NEW_MASTER], vault=new_vault)
    assert "gh-secret" in result.output


def test_backup_with_session_asks_for_a_backup_password(run, tmp_path):
    init_vault(run)
    add_entry(run)
    token = start_session(run)
    backup = str(tmp_path / "vault.vkbak")
    result = run(["backup", "-o", backup], secrets=["backup-pw", "backup-pw"], session=token)
    assert result.exit_code == 0, result.output
    assert os.path.exists(backup)


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


def test_passwd_changes_master_password(run):
    init_vault(run)
    add_entry(run)
    result = run(["passwd"], secrets=[MASTER, NEW_MASTER, NEW_MASTER])
    assert result.exit_code == 0, result.output
    assert run(["list"], secrets=[MASTER]).exit_code == 1
    assert "gh-secret" in run(["get", "-s", "github.com", "--show"], secrets=[NEW_MASTER]).output


def test_passwd_with_wrong_current_password_fails(run):
    init_vault(run)
    result = run(["passwd"], secrets=["wrong"])
    assert result.exit_code == 1


def test_breaches_offline_is_not_reported_clean(run, monkeypatch):
    init_vault(run)
    add_entry(run)
    monkeypatch.setattr(cli_module.BreachChecker, "check_password", lambda self, pw: {
        "error": True, "message": "offline", "found": False, "count": 0})
    result = run(["breaches"], secrets=[MASTER])
    assert result.exit_code == 1
    assert "None of your passwords" not in result.output
    assert "internet connection" in result.output


def test_version_shows_package_version(run):
    from vaultkey import __version__
    result = run(["version"])
    assert __version__ in result.output and "Your Name" not in result.output


def test_status_without_vault(run):
    result = run(["status"])
    assert result.exit_code == 0 and "vk init" in result.output


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


def _json(result):
    text = result.output
    start = min(i for i in (text.find("["), text.find("{")) if i >= 0)
    return text[start:]
