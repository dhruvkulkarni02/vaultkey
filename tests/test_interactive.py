"""Drive interactive mode with scripted answers instead of a terminal"""
import sys
import types

import pytest
import questionary as real_questionary

from vaultkey import interactive
from vaultkey.manager import PasswordManager

MASTER = "correct horse battery staple"


class Script:
    """Stands in for the questionary module; every question pops the next answer"""

    Choice = real_questionary.Choice
    Separator = real_questionary.Separator

    def __init__(self, answers):
        self.answers = list(answers)
        self.asked = []

    def _question(self, kind, message, **kwargs):
        self.asked.append((kind, message))
        if not self.answers:
            raise AssertionError(f"No scripted answer for {kind}: {message}")
        answer = self.answers.pop(0)
        return types.SimpleNamespace(ask=lambda: answer)

    def __getattr__(self, kind):
        if kind in ("select", "text", "confirm", "checkbox", "path"):
            return lambda message, **kwargs: self._question(kind, message, **kwargs)
        raise AttributeError(kind)


@pytest.fixture
def script(monkeypatch):
    def install(*answers):
        fake = Script(answers)
        monkeypatch.setattr(interactive, "questionary", fake)
        monkeypatch.setattr(interactive, "ask_secret", lambda message: fake._question("secret", message).ask())
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
        return fake
    return install


@pytest.fixture
def vault(vault_path):
    pm = PasswordManager(vault_path)
    pm.create_vault(MASTER)
    pm.add_password("github.com", "octocat", "gh-secret")
    pm.lock()
    return vault_path


@pytest.fixture
def clipboard(monkeypatch):
    copied = []
    monkeypatch.setattr(interactive, "copy_with_autoclear", lambda text, timeout: copied.append(text) or True)
    return copied


def test_create_vault_on_first_run(vault_path, script):
    fake = script(MASTER, MASTER, interactive.QUIT)
    interactive.run_interactive(PasswordManager(vault_path))
    assert PasswordManager(vault_path).unlock(MASTER)
    assert not fake.answers


def test_wrong_password_three_times_gives_up(vault, script):
    fake = script("a", "b", "c")
    pm = PasswordManager(vault)
    interactive.run_interactive(pm)
    assert not pm.is_unlocked() and not fake.answers


def test_find_entry_and_copy_password(vault, script, clipboard):
    script(MASTER, interactive.FIND, "github.com", "copy", "copy_user", interactive.BACK, interactive.QUIT)
    interactive.run_interactive(PasswordManager(vault))
    assert clipboard == ["gh-secret", "octocat"]


def test_add_entry_with_generated_password(vault, script, clipboard):
    script(MASTER, interactive.ADD, "gitlab.com", "me", "generate", "24", "", True, interactive.QUIT)
    interactive.run_interactive(PasswordManager(vault))

    pm = PasswordManager(vault)
    pm.unlock(MASTER)
    assert pm.get_password("gitlab.com")["username"] == "me"
    assert len(pm.get_password("gitlab.com")["password"]) == 24
    assert clipboard == [pm.get_password("gitlab.com")["password"]]


def test_edit_rename_and_delete(vault, script):
    script(MASTER, interactive.FIND, "github.com",
           "edit", ["username", "notes"], "newname", "work",
           "rename", "GitHub",
           interactive.BACK, interactive.QUIT)
    interactive.run_interactive(PasswordManager(vault))

    pm = PasswordManager(vault)
    pm.unlock(MASTER)
    assert pm.list_sites() == ["GitHub"]
    assert pm.get_password("GitHub")["username"] == "newname"
    assert pm.get_password("GitHub")["notes"] == "work"

    script(MASTER, interactive.FIND, "GitHub", "delete", True, interactive.QUIT)
    interactive.run_interactive(PasswordManager(vault))
    pm = PasswordManager(vault)
    pm.unlock(MASTER)
    assert pm.list_sites() == []


def test_security_check_lists_problems(vault, script, capsys):
    pm = PasswordManager(vault)
    pm.unlock(MASTER)
    pm.add_password("weak.com", "me", "password")
    pm.add_password("copy.com", "me", "gh-secret")  # reused
    pm.lock()

    script(MASTER, interactive.CHECK, interactive.BACK, interactive.QUIT)
    interactive.run_interactive(PasswordManager(vault))
    output = capsys.readouterr().out
    assert "weak.com" in output and "copy.com" in output and "reused" in output


def test_change_master_password_from_settings(vault, script):
    new = "purple elephant marching quietly"
    script(MASTER, interactive.SETTINGS, "passwd", MASTER, new, new, interactive.BACK, interactive.QUIT)
    interactive.run_interactive(PasswordManager(vault))
    assert PasswordManager(vault).unlock(new)


def test_ctrl_c_at_main_menu_quits(vault, script):
    fake = script(MASTER, None)
    interactive.run_interactive(PasswordManager(vault))
    assert not fake.answers


def test_needs_a_terminal(vault, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit):
        interactive.run_interactive(PasswordManager(vault))


def test_secret_prompts_do_not_echo(monkeypatch):
    prompts = []
    monkeypatch.setattr(interactive.getpass, "getpass", lambda prompt: prompts.append(prompt) or "s3cret")
    assert interactive.ask_secret("Master password:") == "s3cret"
    assert prompts == ["? Master password: "]

    def interrupted(prompt):
        raise KeyboardInterrupt
    monkeypatch.setattr(interactive.getpass, "getpass", interrupted)
    assert interactive.ask_secret("Master password:") is None
