"""
interactive.py - Menu-driven interface (`vk interactive`)

Arrow keys move, Enter selects, typing filters lists, Ctrl-C goes back.
"""
import getpass
import hashlib
import sys
from datetime import datetime
from typing import Dict, List, Optional

import questionary
from questionary import Choice, Separator
from rich.panel import Panel
from rich.table import Table

from . import __version__, ui
from .clipboard import copy_with_autoclear
from .errors import VaultError
from .generator import generate_password
from .manager import PasswordManager
from .session import resume_session
from .strength import PasswordStrength
from .ui import user

CLIPBOARD_TIMEOUT = 30
_analyzer = PasswordStrength()

# Menu values
FIND, ADD, GENERATE, CHECK, SETTINGS, QUIT = "find", "add", "generate", "check", "settings", "quit"
BACK = "back"


def ask(question):
    """Ask a questionary question; None means the user pressed Ctrl-C"""
    return question.ask()


def ask_secret(message: str) -> Optional[str]:
    """Prompt for a secret without echoing anything (not even its length); None on Ctrl-C"""
    try:
        return getpass.getpass(f"? {message} ")
    except (KeyboardInterrupt, EOFError):
        return None


def run_interactive(pm: PasswordManager) -> None:
    """Entry point for `vk interactive`"""
    if not sys.stdin.isatty():
        ui.fail("Interactive mode needs a terminal. Use the 'vk' commands in scripts.")

    ui.console.print(Panel.fit(f"[bold cyan]VaultKey[/] {__version__}\n[dim]Local, encrypted password manager[/]",
                               border_style="cyan"))

    if not pm.storage.exists():
        ui.info("No vault yet. Let's create one.")
        if not create_vault(pm):
            return
    elif not unlock(pm):
        return

    main_menu(pm)
    ui.success("Vault locked. Goodbye!")


# --- Unlocking ---------------------------------------------------------------

def create_vault(pm: PasswordManager) -> bool:
    ui.info("Choose a master password. It protects everything and [bold]cannot be recovered[/] if forgotten.")
    password = ask_secret("Master password:")
    if not password:
        return False
    if ask_secret("Confirm master password:") != password:
        ui.error("Passwords don't match")
        return False
    if len(password) < 12 or _analyzer.analyze(password)['score'] < 60:
        ui.warning("This master password is weak. A passphrase of several random words is stronger.")
        if not ask(questionary.confirm("Use it anyway?", default=False)):
            return False
    pm.create_vault(password)
    ui.success(f"Vault created at {user(pm.storage.filename)}")
    return True


def unlock(pm: PasswordManager) -> bool:
    crypto = resume_session(pm.storage.filename)
    if crypto is not None and pm.unlock_with_crypto(crypto):
        ui.success("Unlocked with your 'vk unlock' session")
        return True

    for _ in range(3):
        password = ask_secret("Master password:")
        if password is None:
            return False
        try:
            with ui.err_console.status("Unlocking…"):
                unlocked = pm.unlock(password)
        except VaultError as e:
            ui.error(str(e))
            return False
        if unlocked:
            if pm.migrated_from_version:
                ui.warning("Your vault was upgraded to the new format. Consider changing your master password.")
            return True
        ui.error("Wrong master password")
    return False


# --- Main menu ---------------------------------------------------------------

def vault_health(pm: PasswordManager) -> Dict[str, List[str]]:
    """Sites with weak, reused or old passwords"""
    weak, reused, old = [], [], []
    seen: Dict[str, str] = {}
    for site in pm.list_sites():
        entry = pm.get_password(site)
        if _analyzer.analyze(entry['password'])['score'] < 60:
            weak.append(site)
        fingerprint = hashlib.sha256(entry['password'].encode()).hexdigest()
        if fingerprint in seen:
            reused.extend(s for s in (seen[fingerprint], site) if s not in reused)
        seen.setdefault(fingerprint, site)
        age = ui.age_in_days(entry.get('modified'))
        if age is not None and age > ui.OLD_AFTER_DAYS:
            old.append(site)
    return {"weak": weak, "reused": reused, "old": old}


def status_line(pm: PasswordManager, health: Dict[str, List[str]]) -> str:
    count = len(pm.list_sites())
    parts = [f"[bold]{count}[/] entr{'y' if count == 1 else 'ies'}"]
    problems = [f"[yellow]{len(sites)} {name}[/]" for name, sites in health.items() if sites]
    parts.append(" · ".join(problems) if problems else "[green]no problems found[/]")
    return " · ".join(parts)


def main_menu(pm: PasswordManager) -> None:
    while True:
        health = vault_health(pm)
        ui.console.print()
        ui.console.print(status_line(pm, health))
        choice = ask(questionary.select(
            "What would you like to do?",
            choices=[
                Choice("Find an entry", FIND),
                Choice("Add an entry", ADD),
                Choice("Generate a password", GENERATE),
                Choice("Security check", CHECK),
                Choice("Settings", SETTINGS),
                Separator(),
                Choice("Lock and quit", QUIT),
            ],
        ))
        if choice in (None, QUIT):
            return
        if choice == FIND:
            site = pick_entry(pm, pm.list_sites())
            if site:
                entry_menu(pm, site)
        elif choice == ADD:
            add_entry(pm)
        elif choice == GENERATE:
            generator_menu()
        elif choice == CHECK:
            security_check(pm, health)
        elif choice == SETTINGS:
            settings_menu(pm)


def pick_entry(pm: PasswordManager, sites: List[str], message: str = "Type to filter, Enter to open:") -> Optional[str]:
    if not sites:
        ui.info("Your vault is empty. Choose 'Add an entry' to add one.")
        return None
    choices = [Choice(f"{site}  ·  {pm.get_password(site).get('username', '')}", site) for site in sites]
    choices += [Separator(), Choice("← Back", BACK)]
    site = ask(questionary.select(message, choices=choices, use_search_filter=True, use_jk_keys=False))
    return None if site in (None, BACK) else site


# --- One entry ---------------------------------------------------------------

def show_entry(pm: PasswordManager, site: str, reveal: bool = False) -> None:
    entry = pm.get_password(site)
    score = _analyzer.analyze(entry['password'])['score']
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Username", f"[cyan]{user(entry.get('username', ''))}[/]")
    grid.add_row("Password", f"[yellow]{user(entry['password'])}[/]" if reveal else ui.MASK)
    grid.add_row("Strength", ui.strength_text(score))
    if entry.get('notes'):
        grid.add_row("Notes", user(entry['notes']))
    grid.add_row("Modified", f"{entry.get('modified', '')[:10]} [dim]({ui.format_age(ui.age_in_days(entry.get('modified')))})[/]")
    if entry.get('history'):
        grid.add_row("History", f"{len(entry['history'])} previous password(s)")
    ui.console.print(Panel(grid, title=f"[bold]{user(site)}[/]", title_align="left", border_style="cyan", expand=False))


def entry_menu(pm: PasswordManager, site: str) -> None:
    reveal = False
    redraw = True
    while True:
        if redraw:
            show_entry(pm, site, reveal)
        redraw = True
        entry = pm.get_password(site)
        choice = ask(questionary.select(
            "Action:",
            choices=[
                Choice("Copy password", "copy"),
                Choice("Copy username", "copy_user"),
                Choice("Hide password" if reveal else "Show password", "reveal"),
                Choice("Edit", "edit"),
                Choice("Password history", "history"),
                Choice("Rename", "rename"),
                Choice("Delete", "delete"),
                Separator(),
                Choice("← Back", BACK),
            ],
        ))
        if choice in (None, BACK):
            return
        if choice in ("copy", "copy_user"):
            # Nothing on screen changes, so don't print the entry again
            redraw = False
            if choice == "copy":
                copy(entry['password'], "Password")
            else:
                copy(entry.get('username', ''), "Username")
        elif choice == "reveal":
            reveal = not reveal
        elif choice == "edit":
            edit_entry(pm, site)
        elif choice == "history":
            show_history(pm, site)
        elif choice == "rename":
            new_name = ask(questionary.text("New name:", default=site))
            if new_name and new_name != site:
                try:
                    pm.rename_entry(site, new_name)
                    ui.success(f"Renamed to {user(new_name)}")
                    site = new_name
                except ValueError as e:
                    ui.error(str(e))
        elif choice == "delete":
            if ask(questionary.confirm(f"Delete {site}? This cannot be undone", default=False)):
                pm.delete_password(site)
                ui.success(f"Deleted {user(site)}")
                return


def copy(text: str, what: str) -> None:
    try:
        copied = copy_with_autoclear(text, CLIPBOARD_TIMEOUT)
    except Exception:
        copied = False
    if copied:
        ui.success(f"{what} copied, clears in {CLIPBOARD_TIMEOUT}s")
    else:
        ui.error("Clipboard not available (install pyperclip, and xclip or wl-clipboard on Linux)")


def ask_new_password(site: str = "") -> Optional[str]:
    """Generate or type a password; None if cancelled"""
    how = ask(questionary.select("Password:", choices=[
        Choice("Generate a strong one", "generate"),
        Choice("Type it in", "type"),
    ]))
    if how is None:
        return None
    if how == "generate":
        length = ask(questionary.text("Length:", default="20", validate=_valid_length))
        if length is None:
            return None
        password = generate_password(int(length))
        ui.console.print(f"Generated: [bold green]{user(password)}[/]")
        return password

    password = ask_secret("Password:")
    if not password:
        return None
    if ask_secret("Confirm password:") != password:
        ui.error("Passwords don't match")
        return None
    score = _analyzer.analyze(password)['score']
    ui.console.print(f"Strength: {ui.strength_text(score)}")
    return password


def _valid_length(text: str):
    return (text.isdigit() and 4 <= int(text) <= 256) or "Enter a number from 4 to 256"


def add_entry(pm: PasswordManager) -> None:
    site = ask(questionary.text("Site or service:", validate=lambda t: bool(t.strip()) or "Required"))
    if not site:
        return
    site = site.strip()
    if pm.get_password(site) and not ask(questionary.confirm(
            f"{site} already exists. Replace it? (The old password goes to its history)", default=False)):
        return
    username = ask(questionary.text("Username or email:"))
    if username is None:
        return
    password = ask_new_password(site)
    if password is None:
        return
    notes = ask(questionary.text("Notes (optional):")) or ""

    pm.add_password(site, username, password, notes)
    ui.success(f"Saved {user(site)}")
    if ask(questionary.confirm("Copy the password now?", default=True)):
        copy(password, "Password")


def edit_entry(pm: PasswordManager, site: str) -> None:
    entry = pm.get_password(site)
    fields = ask(questionary.checkbox("What do you want to change?", choices=[
        Choice("Password", "password"), Choice("Username", "username"), Choice("Notes", "notes"),
    ]))
    if not fields:
        return
    new_password = new_username = new_notes = None
    if "username" in fields:
        new_username = ask(questionary.text("Username:", default=entry.get('username', '')))
    if "notes" in fields:
        new_notes = ask(questionary.text("Notes:", default=entry.get('notes', '')))
    if "password" in fields:
        new_password = ask_new_password(site)
        if new_password and pm.check_password_reuse(site, new_password):
            ui.warning("You have used this password for this entry before.")
    if new_password is None and new_username is None and new_notes is None:
        return
    pm.update_password(site, new_password=new_password, new_username=new_username, new_notes=new_notes)
    ui.success(f"Updated {user(site)}")


def show_history(pm: PasswordManager, site: str) -> None:
    entries = pm.get_password_history(site)
    if not entries:
        ui.info("No previous passwords")
        return
    reveal = ask(questionary.confirm("Show the old passwords?", default=False))
    table = ui.new_table("#", "Password", "In use from", "Replaced")
    for number, item in enumerate(reversed(entries), 1):
        table.add_row(str(number), f"[yellow]{user(item['password'])}[/]" if reveal else ui.MASK,
                      item.get('changed', '')[:10], item.get('retired', '')[:10])
    ui.console.print(table)


# --- Tools -------------------------------------------------------------------

def generator_menu() -> None:
    options = {"length": 20, "symbols": True, "digits": True, "uppercase": True, "no_ambiguous": False}
    while True:
        password = generate_password(
            options["length"], use_uppercase=options["uppercase"], use_digits=options["digits"],
            use_symbols=options["symbols"], exclude_ambiguous=options["no_ambiguous"])
        score = _analyzer.analyze(password)['score']
        ui.console.print(Panel.fit(f"[bold green]{user(password)}[/]\n{ui.strength_text(score)}",
                                   title="Generated password", border_style="green"))
        choice = ask(questionary.select("Action:", choices=[
            Choice("Copy", "copy"), Choice("Generate another", "again"), Choice("Change options", "options"),
            Separator(), Choice("← Back", BACK),
        ]))
        if choice in (None, BACK):
            return
        if choice == "copy":
            copy(password, "Password")
        elif choice == "options":
            length = ask(questionary.text("Length:", default=str(options["length"]), validate=_valid_length))
            kinds = ask(questionary.checkbox("Include:", choices=[
                Choice("Uppercase letters", "uppercase", checked=options["uppercase"]),
                Choice("Digits", "digits", checked=options["digits"]),
                Choice("Symbols", "symbols", checked=options["symbols"]),
                Choice("Avoid look-alikes (0 O 1 l I)", "no_ambiguous", checked=options["no_ambiguous"]),
            ]))
            if length is not None:
                options["length"] = int(length)
            if kinds is not None:
                for key in ("uppercase", "digits", "symbols", "no_ambiguous"):
                    options[key] = key in kinds


def security_check(pm: PasswordManager, health: Dict[str, List[str]]) -> None:
    problems: Dict[str, List[str]] = {}
    for label, sites in (("weak", health["weak"]), ("reused", health["reused"]), ("old", health["old"])):
        for site in sites:
            problems.setdefault(site, []).append(label)

    if not problems:
        ui.success("No weak, reused or old passwords. Nice!")
        ui.info("Run 'vk audit -b' to also check for breached passwords.")
        return

    table = ui.new_table("Site", "Strength", "Issues", title="Entries that need attention")
    for site in sorted(problems):
        score = _analyzer.analyze(pm.get_password(site)['password'])['score']
        table.add_row(f"[bold]{user(site)}[/]", ui.strength_text(score), ", ".join(problems[site]))
    ui.console.print(table)

    site = pick_entry(pm, sorted(problems), "Open one to fix it:")
    if site:
        entry_menu(pm, site)


def settings_menu(pm: PasswordManager) -> None:
    while True:
        choice = ask(questionary.select("Settings:", choices=[
            Choice("Change master password", "passwd"),
            Choice("Create a backup", "backup"),
            Choice("Vault information", "info"),
            Separator(),
            Choice("← Back", BACK),
        ]))
        if choice in (None, BACK):
            return
        if choice == "passwd":
            change_master_password(pm)
        elif choice == "backup":
            create_backup(pm)
        elif choice == "info":
            vault_info(pm)


def change_master_password(pm: PasswordManager) -> None:
    current = ask_secret("Current master password:")
    if not current:
        return
    new = ask_secret("New master password:")
    if not new:
        return
    if ask_secret("Confirm new master password:") != new:
        ui.error("New passwords don't match")
        return
    if len(new) < 12 or _analyzer.analyze(new)['score'] < 60:
        ui.warning("The new master password is weak.")
        if not ask(questionary.confirm("Use it anyway?", default=False)):
            return
    try:
        with ui.err_console.status("Re-encrypting…"):
            changed = pm.change_master_password(current, new)
    except VaultError as e:
        ui.error(str(e))
        return
    if changed:
        from .session import end_session
        end_session(pm.storage.filename)
        ui.success("Master password changed. Existing backups keep their old password.")
    else:
        ui.error("The current master password is wrong")


def create_backup(pm: PasswordManager) -> None:
    default_path = f"vaultkey_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.vkbak"
    path = ask(questionary.path("Save the backup to:", default=default_path))
    if not path:
        return
    password = ask_secret("Backup password (can be your master password):")
    if not password:
        return
    if ask_secret("Confirm backup password:") != password:
        ui.error("Passwords don't match")
        return
    try:
        with ui.err_console.status("Encrypting backup…"):
            pm.create_secure_backup(password, path)
    except (VaultError, ValueError, OSError) as e:
        ui.error(f"Backup failed: {user(e)}")
        return
    ui.success(f"Backup saved to {user(path)}. Keep it somewhere other than this computer.")


def vault_info(pm: PasswordManager) -> None:
    info = pm.get_vault_info()
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Location", user(pm.storage.filename))
    grid.add_row("Created", str(info['created'])[:10])
    grid.add_row("Entries", str(info['password_count']))
    grid.add_row("Old passwords kept", str(info['history_entries']))
    if info.get('file_info'):
        grid.add_row("File size", f"{info['file_info']['size']:,} bytes")
    ui.console.print(Panel(grid, title="Vault", title_align="left", border_style="cyan", expand=False))
