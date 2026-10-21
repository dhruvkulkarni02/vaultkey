"""Drive the full-screen app headlessly with Textual's test pilot"""
import asyncio
import io
import time

import pytest
from rich.console import Console
from textual.widgets import Checkbox, Input, Select, Static

from vaultkey import app as app_module
from vaultkey.app import (
    ChangePasswordScreen,
    CreateVaultScreen,
    EntryFormScreen,
    ExportScreen,
    HelpScreen,
    ImportScreen,
    UnlockScreen,
    VaultKeyApp,
    VaultScreen,
)
from vaultkey.manager import PasswordManager
from vaultkey.portability import VaultImporter
from vaultkey.session import start_session

MASTER = "correct horse battery staple"


@pytest.fixture
def pm(vault_path):
    manager = PasswordManager(vault_path)
    manager.create_vault(MASTER)
    manager.add_password("github.com", "octocat", "gh-secret-Xq7#vB2!", "work")
    manager.add_password("gitlab.com", "me", "password")
    manager.add_password("figma.com", "me", "gh-secret-Xq7#vB2!")
    manager.lock()
    return manager


@pytest.fixture
def clipboard(monkeypatch):
    copied = []
    monkeypatch.setattr(app_module, "copy_with_autoclear", lambda text, timeout: copied.append(text) or True)
    return copied


def run(pm, scenario, unlock=True):
    async def main():
        app = VaultKeyApp(pm)
        async with app.run_test(size=(130, 42)) as pilot:
            await pilot.pause()
            if unlock:
                await type_and_submit(app, pilot, "#password", MASTER)
                assert isinstance(app.screen, VaultScreen)
            await scenario(app, pilot)
    asyncio.run(main())


async def click(pilot, selector):
    """Click, then wait out the button's pressed effect (Textual ignores clicks during it)"""
    await pilot.click(selector)
    await pilot.pause(0.3)


async def settle(app, pilot):
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


async def type_and_submit(app, pilot, selector, text):
    field = app.screen.query_one(selector, Input)
    field.focus()
    field.value = text
    await pilot.press("enter")
    await settle(app, pilot)


def table_sites(app):
    return list(app.screen.visible_sites)


def plain(widget):
    """The text a Static shows, without styling"""
    console = Console(width=120, file=io.StringIO(), record=True)
    console.print(widget.content)
    return console.export_text()


def detail_text(app):
    return plain(app.screen.query_one("#detail-body", Static))


def test_create_vault_on_first_run(vault_path):
    pm = PasswordManager(vault_path)

    async def scenario(app, pilot):
        assert isinstance(app.screen, CreateVaultScreen)
        app.screen.query_one("#password", Input).value = MASTER
        app.screen.query_one("#confirm", Input).value = "different"
        await click(pilot, "#create")
        assert "match" in plain(app.screen.query_one("#message", Static))
        app.screen.query_one("#confirm", Input).value = MASTER
        await click(pilot, "#create")
        await settle(app, pilot)
        assert isinstance(app.screen, VaultScreen)
        assert "empty" in detail_text(app)

    run(pm, scenario, unlock=False)
    assert PasswordManager(vault_path).unlock(MASTER)


def test_weak_master_password_needs_confirmation(vault_path):
    pm = PasswordManager(vault_path)

    async def scenario(app, pilot):
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = "short"
        await click(pilot, "#create")
        assert isinstance(app.screen, CreateVaultScreen)
        app.screen.query_one("#accept-weak", Checkbox).value = True
        await click(pilot, "#create")
        await settle(app, pilot)
        assert isinstance(app.screen, VaultScreen)

    run(pm, scenario, unlock=False)


def test_wrong_password_then_right(pm):
    async def scenario(app, pilot):
        await type_and_submit(app, pilot, "#password", "wrong")
        assert isinstance(app.screen, UnlockScreen)
        assert "Wrong master password" in plain(app.screen.query_one("#message", Static))
        await type_and_submit(app, pilot, "#password", MASTER)
        assert isinstance(app.screen, VaultScreen)

    run(pm, scenario, unlock=False)


def test_list_search_and_copy(pm, clipboard):
    async def scenario(app, pilot):
        assert table_sites(app) == ["figma.com", "github.com", "gitlab.com"]
        await pilot.press("slash")
        app.screen.query_one("#search", Input).value = "git"
        await pilot.pause()
        assert table_sites(app) == ["github.com", "gitlab.com"]
        await pilot.press("enter")          # back to the list
        await pilot.press("c", "u")
        assert clipboard == ["gh-secret-Xq7#vB2!", "octocat"]
        await pilot.press("down", "enter")  # Enter on a row copies its password
        assert clipboard[-1] == "password"
        await pilot.press("escape")
        assert len(table_sites(app)) == 3

    run(pm, scenario)


def test_detail_reveal_and_issues(pm):
    async def scenario(app, pilot):
        await pilot.press("down")           # github.com
        text = detail_text(app)
        assert "octocat" in text and "gh-secret" not in text
        assert "REUSED" in text and "figma.com" in text
        await pilot.press("r")
        assert "gh-secret-Xq7#vB2!" in detail_text(app)
        await pilot.press("down")           # moving hides it again
        await pilot.press("up")
        assert "gh-secret" not in detail_text(app)

    run(pm, scenario)


def test_problems_filter(pm):
    async def scenario(app, pilot):
        await pilot.press("f")
        assert set(table_sites(app)) == {"figma.com", "github.com", "gitlab.com"}  # reused, reused, weak
        app.pm.update_password("figma.com", new_password="Unique-Pz4!Wn8@Kc2#")
        app.screen.refresh_entries()
        assert table_sites(app) == ["gitlab.com"]
        await pilot.press("f")
        assert len(table_sites(app)) == 3

    run(pm, scenario)


def test_add_edit_and_delete(pm):
    async def scenario(app, pilot):
        await pilot.press("n")
        form = app.screen
        assert isinstance(form, EntryFormScreen)
        form.query_one("#site", Input).value = "github.com"
        form.query_one("#password", Input).value = "x"
        await pilot.press("ctrl+s")
        assert "already exists" in plain(form.query_one("#error", Static))
        form.query_one("#site", Input).value = "example.org"
        form.query_one("#username", Input).value = "alex"
        form.query_one("#password", Input).value = "Ex4mple!Pass#word"
        form.query_one("#notes", Input).value = "test"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert isinstance(app.screen, VaultScreen)
        assert app.pm.get_password("example.org")["username"] == "alex"
        assert app.screen.current_site() == "example.org"

        await pilot.press("e")
        app.screen.query_one("#site", Input).value = "example.com"
        app.screen.query_one("#password", Input).value = "N3w!Pass#word-2"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert "example.org" not in app.pm.list_sites()
        assert app.pm.get_password("example.com")["password"] == "N3w!Pass#word-2"
        assert app.pm.get_password_history("example.com")[0]["password"] == "Ex4mple!Pass#word"

        await pilot.press("d")
        await pilot.press("y")
        await pilot.pause()
        assert "example.com" not in app.pm.list_sites()

    run(pm, scenario)


def test_generator_fills_the_form(pm):
    async def scenario(app, pilot):
        await pilot.press("n")
        await pilot.press("ctrl+g")
        await pilot.pause()
        generated = app.screen.password
        assert len(generated) == 20
        await click(pilot, "#use")
        await pilot.pause()
        assert app.screen.query_one("#password", Input).value == generated

    run(pm, scenario)


def test_import_csv(pm, tmp_path):
    csv_file = tmp_path / "chrome.csv"
    csv_file.write_text("name,url,username,password\nNew Site,https://new.example,me,s3cret!\n"
                        "github.com,https://github.com,x,y\n")

    async def scenario(app, pilot):
        await pilot.press("i")
        assert isinstance(app.screen, ImportScreen)
        app.screen.query_one("#path", Input).value = str(csv_file)
        await pilot.pause()
        preview = plain(app.screen.query_one("#preview", Static))
        assert "Found 2 entries" in preview and "1 already in your vault" in preview
        await click(pilot, "#import")
        await pilot.pause()
        assert isinstance(app.screen, VaultScreen)
        assert app.pm.get_password("New Site")["password"] == "s3cret!"
        assert app.pm.get_password("github.com")["username"] == "octocat"  # existing entry untouched

    run(pm, scenario)


def test_export_encrypted_roundtrip(pm, tmp_path):
    target = tmp_path / "export.vkexport"

    async def scenario(app, pilot):
        await pilot.press("x")
        screen = app.screen
        assert isinstance(screen, ExportScreen)
        screen.query_one("#path", Input).value = str(target)
        screen.query_one("#export-password", Input).value = "export-pw"
        screen.query_one("#export-confirm", Input).value = "export-pw"
        await click(pilot, "#export")
        await settle(app, pilot)
        assert isinstance(app.screen, VaultScreen)

    run(pm, scenario)
    entries = VaultImporter().import_file(str(target), "vaultkey", "export-pw")
    assert entries["github.com"]["password"] == "gh-secret-Xq7#vB2!"


def test_export_csv_hides_passwords_unless_asked(pm, tmp_path):
    target = tmp_path / "export.csv"

    async def scenario(app, pilot):
        await pilot.press("x")
        screen = app.screen
        screen.query_one("#format", Select).value = "csv"
        await pilot.pause()
        assert screen.query_one("#export-password").has_class("hidden")
        screen.query_one("#path", Input).value = str(target)
        await click(pilot, "#export")
        await settle(app, pilot)

    run(pm, scenario)
    assert "***HIDDEN***" in target.read_text() and "gh-secret" not in target.read_text()


def test_backup(pm, tmp_path):
    target = tmp_path / "vault.vkbak"

    async def scenario(app, pilot):
        await pilot.press("b")
        app.screen.query_one("#path", Input).value = str(target)
        app.screen.query_one("#password", Input).value = "backup-pw"
        app.screen.query_one("#confirm", Input).value = "backup-pw"
        await click(pilot, "#create")
        await settle(app, pilot)

    run(pm, scenario)
    restored = PasswordManager(str(tmp_path / "restored"))
    restored.restore_from_backup(str(target), "backup-pw", master_password=MASTER)
    assert restored.get_password("github.com")["username"] == "octocat"


def test_change_master_password(pm, vault_path):
    new = "purple elephant marching quietly"

    async def scenario(app, pilot):
        await pilot.press("p")
        screen = app.screen
        assert isinstance(screen, ChangePasswordScreen)
        screen.query_one("#current", Input).value = "wrong"
        screen.query_one("#new", Input).value = new
        screen.query_one("#confirm", Input).value = new
        await click(pilot, "#change")
        await settle(app, pilot)
        assert "wrong" in plain(screen.query_one("#error", Static))
        assert app.pm.is_unlocked()
        screen.query_one("#current", Input).value = MASTER
        await click(pilot, "#change")
        await settle(app, pilot)
        assert isinstance(app.screen, VaultScreen)

    run(pm, scenario)
    assert PasswordManager(vault_path).unlock(new)


def test_idle_auto_lock(pm):
    async def scenario(app, pilot):
        await pilot.press("n")              # a dialog is open
        app.last_activity = time.monotonic() - 6 * 60
        app.check_inactivity()
        await pilot.pause()
        assert isinstance(app.screen, UnlockScreen)
        assert not app.pm.is_unlocked()
        assert "idle" in plain(app.screen.query_one("#message", Static))

    run(pm, scenario)


def test_lock_key_and_help(pm):
    async def scenario(app, pilot):
        await pilot.press("question_mark")
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        await pilot.press("l")
        await pilot.pause()
        assert isinstance(app.screen, UnlockScreen)

    run(pm, scenario)


def test_session_skips_unlock(pm, vault_path, monkeypatch):
    unlocked = PasswordManager(vault_path)
    unlocked.unlock(MASTER)
    monkeypatch.setenv("VAULTKEY_SESSION", start_session(unlocked.crypto, vault_path))

    async def scenario(app, pilot):
        assert isinstance(app.screen, VaultScreen)

    run(PasswordManager(vault_path), scenario, unlock=False)


def test_user_text_is_shown_literally(vault_path):
    pm = PasswordManager(vault_path)
    pm.create_vault(MASTER)
    pm.add_password("[bold]odd[/bold]", "[red]me", "Pz4!Wn8@Kc2#Qr6$")
    pm.lock()

    async def scenario(app, pilot):
        assert "[bold]odd[/bold]" in detail_text(app)
        assert "[red]me" in detail_text(app)

    run(pm, scenario)


def test_needs_a_terminal(pm, monkeypatch):
    monkeypatch.setattr(app_module.sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit):
        app_module.run_app(pm)
