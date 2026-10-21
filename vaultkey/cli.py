#!/usr/bin/env python3
"""
VaultKey - Secure Password Manager CLI
"""
import functools
import getpass
import hashlib
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

import click
from click.shell_completion import CompletionItem, get_completion_class
from rich.table import Table

from . import __author__, __version__
from . import ui
from .breach import BreachChecker
from .clipboard import copy_with_autoclear, run_clearer
from .errors import VaultError
from .generator import generate_password
from .manager import PasswordManager, default_vault_path
from .portability import VaultExporter, VaultImporter
from .session import (
    DEFAULT_TIMEOUT_MINUTES,
    SESSION_ENV,
    end_session,
    resume_session,
    session_expiry,
    start_session,
)
from .strength import PasswordStrength
from .ui import user

# Initialize password manager with default vault file
DEFAULT_VAULT = default_vault_path()
pm = None


def get_password_manager() -> PasswordManager:
    """Get or create password manager instance"""
    global pm
    if pm is None:
        pm = PasswordManager(DEFAULT_VAULT)
    return pm


# --- Unlocking ---------------------------------------------------------------

def prompt_master_password(confirm: bool = False) -> Optional[str]:
    """Prompt for master password with optional confirmation"""
    password = getpass.getpass("Master password: ")

    if confirm:
        confirm_password = getpass.getpass("Confirm master password: ")
        if password != confirm_password:
            ui.error("Passwords don't match")
            return None

    return password


def prompt_new_master_password() -> Optional[str]:
    """Prompt for a new master password, warning about weak ones"""
    password = prompt_master_password(confirm=True)
    if password is None:
        return None
    if not password:
        ui.error("The master password must not be empty")
        return None

    score = PasswordStrength().analyze(password)['score']
    if len(password) < 12 or score < 60:
        ui.warning("This master password is weak. Anyone who copies your vault file can try to guess it offline.")
        ui.info("A long passphrase of several random words is strong and easy to remember.")
        if not click.confirm("Use it anyway?", default=False, err=True):
            return None
    return password


def unlock_with_password(pm: PasswordManager) -> str:
    """Prompt for the master password and unlock the vault, or exit with an error.

    Returns:
        The master password
    """
    password = prompt_master_password()
    try:
        if password and pm.unlock(password):
            if pm.migrated_from_version:
                ui.success("Your vault was upgraded to the new format.")
                ui.warning("If old copies of the vault file may exist, change your master password with 'vk passwd'.")
            return password
        ui.error("Invalid master password!")
    except VaultError as e:
        ui.error(str(e))
    sys.exit(1)


def open_vault(pm: PasswordManager) -> Optional[str]:
    """Unlock the vault with the active `vk unlock` session, or by prompting.

    Returns:
        The master password if it was prompted for, None if a session was used
    """
    if not pm.storage.exists():
        ui.fail(f"No vault found at {user(pm.storage.filename)}. Create one with 'vk init'.")

    crypto = resume_session(pm.storage.filename)
    if crypto is not None and pm.unlock_with_crypto(crypto):
        return None
    return unlock_with_password(pm)


def with_vault(command):
    """Run a command with the vault unlocked, passing the manager as `pm`, and lock it afterwards"""
    @functools.wraps(command)
    def wrapper(*args, **kwargs):
        manager = get_password_manager()
        open_vault(manager)
        try:
            return command(manager, *args, **kwargs)
        except (VaultError, ValueError, OSError) as e:
            ui.fail(user(str(e)))
        finally:
            manager.lock()
    return wrapper


def resolve_site(pm: PasswordManager, query: str) -> str:
    """Find the entry the user means: an exact name, or the only partial match.
    Exits with an error when there is no match or several."""
    if pm.get_password(query):
        return query

    matches = pm.search_sites(query)
    if len(matches) == 1:
        ui.info(f"Using [bold]{user(matches[0])}[/]")
        return matches[0]
    if not matches:
        ui.fail(f"No entry matches '{user(query)}'")

    ui.error(f"'{user(query)}' matches {len(matches)} entries:")
    for match in matches[:10]:
        ui.err_console.print(f"    {user(match)}")
    if len(matches) > 10:
        ui.err_console.print(f"    … and {len(matches) - 10} more")
    ui.fail("Use the full name of the entry")


def complete_site(ctx, param, incomplete: str) -> List[CompletionItem]:
    """Shell completion for entry names. Only works while a `vk unlock` session is active."""
    try:
        manager = PasswordManager(DEFAULT_VAULT)
        crypto = resume_session(manager.storage.filename)
        if crypto is None or not manager.unlock_with_crypto(crypto):
            return []
        try:
            return [CompletionItem(site) for site in manager.list_sites()
                    if site.lower().startswith(incomplete.lower())]
        finally:
            manager.lock()
    except Exception:
        return []


def secure_clipboard_copy(password: str, timeout: int = 30) -> bool:
    """Copy password to clipboard; it is cleared (and the previous content restored)
    after `timeout` seconds, even if this process has exited by then"""
    try:
        return copy_with_autoclear(password, timeout)
    except Exception:
        return False


def copy_or_warn(text: str, what: str, timeout: int = 30) -> None:
    if secure_clipboard_copy(text, timeout):
        clears = f", clears in {timeout}s" if timeout > 0 else ""
        ui.success(f"{what} copied to clipboard{clears}")
    else:
        ui.fail("Clipboard not available. Install 'pyperclip' (and xclip or wl-clipboard on Linux).")


def describe_entry(site: str, entry: dict, show_password: bool) -> Table:
    """Key/value view of one entry"""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Site", f"[bold]{user(site)}[/]")
    grid.add_row("Username", f"[cyan]{user(entry.get('username', ''))}[/]")
    grid.add_row("Password", f"[yellow]{user(entry['password'])}[/]" if show_password
                 else f"{ui.MASK} [dim](--show to display, --copy to copy)[/]")
    if entry.get("notes"):
        grid.add_row("Notes", user(entry["notes"]))
    for field in ("created", "modified"):
        if entry.get(field):
            grid.add_row(field.capitalize(), f"{entry[field][:10]} [dim]({ui.format_age(ui.age_in_days(entry[field]))})[/]")
    if entry.get("history"):
        grid.add_row("History", f"{len(entry['history'])} previous password(s) [dim](vk history)[/]")
    return grid


SITE_ARGUMENT = functools.partial(click.argument, 'site', shell_complete=complete_site)


# --- Commands ----------------------------------------------------------------

@click.group(context_settings={"help_option_names": ["-h", "--help"]}, invoke_without_command=True)
@click.version_option(version=__version__, prog_name="VaultKey")
@click.pass_context
def cli(ctx):
    """VaultKey - a local, offline password manager

    Argon2id key derivation and AES-256-GCM encryption. Your passwords are
    encrypted locally and never leave your device.

    Run 'vk' on its own to open the full-screen app, or use the commands below.
    'vk unlock' keeps the vault unlocked between commands.
    """
    if ctx.invoked_subcommand is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            ctx.invoke(interactive)
        else:
            click.echo(ctx.get_help())


@cli.command()
def init():
    """Create a new password vault"""
    pm = get_password_manager()

    if pm.storage.exists():
        ui.warning(f"A vault already exists at {user(pm.storage.filename)}")
        if not click.confirm("Delete it and create a new, empty vault? This cannot be undone", default=False, err=True):
            return

        # Delete existing vault (and the salt file VaultKey 1.0 kept beside it)
        pm.storage.delete()
        end_session(pm.storage.filename)
        if os.path.exists(pm.legacy_salt_file):
            os.remove(pm.legacy_salt_file)

    ui.info("Choose a master password. It protects every entry and [bold]cannot be recovered[/] if you forget it.")
    password = prompt_new_master_password()
    if not password:
        sys.exit(1)

    try:
        pm.create_vault(password)
    except (VaultError, ValueError, OSError) as e:
        ui.fail(f"Could not create the vault: {user(e)}")
    ui.success(f"Vault created at {user(pm.storage.filename)}")
    ui.info("Add your first password with 'vk add', or try 'vk interactive'.")


@cli.command()
@click.option('--site', '-s', prompt="Site/Service", help='Website or service name')
@click.option('--username', '-u', prompt="Username", help='Username or email')
@click.option('--generate', '-g', is_flag=True, help='Generate a secure password')
@click.option('--length', '-l', default=16, type=click.IntRange(4, 256), help='Generated password length')
@click.option('--no-symbols', is_flag=True, help='Exclude symbols from generated password')
@click.option('--notes', '-n', help='Optional notes about this account')
@click.option('--copy', '-c', is_flag=True, help='Copy the password to the clipboard after saving')
@with_vault
def add(pm, site, username, generate, length, no_symbols, notes, copy):
    """Add a new password to the vault"""
    if pm.get_password(site):
        ui.warning(f"An entry for {user(site)} already exists; its current password will move to its history.")
        if not click.confirm("Replace it?", default=False, err=True):
            return

    if generate:
        password = generate_password(length, use_symbols=not no_symbols)
        ui.console.print(f"Generated password: [bold green]{user(password)}[/]")
        if not click.confirm("Save this password?", default=True, err=True):
            ui.info("Not saved.")
            return
    else:
        password = getpass.getpass("Password: ")
        if not password:
            ui.fail("The password must not be empty")
        if getpass.getpass("Confirm password: ") != password:
            ui.fail("Passwords don't match")

    pm.add_password(site, username, password, notes)
    ui.success(f"Saved [bold]{user(site)}[/]")
    if copy:
        copy_or_warn(password, "Password")


@cli.command()
@click.option('--site', '-s', required=True, shell_complete=complete_site, help='Website or service name')
@click.option('--show', '-S', is_flag=True, help='Show password in plain text')
@click.option('--copy', '-c', is_flag=True, help='Copy password to clipboard')
@click.option('--json', 'as_json', is_flag=True, help='Print the entry, including its password, as JSON')
@with_vault
def get(pm, site, show, copy, as_json):
    """Retrieve a password from the vault"""
    site = resolve_site(pm, site)
    entry = pm.get_password(site)

    if as_json:
        ui.print_json(ui.entry_json(site, entry, include_password=True))
    else:
        ui.console.print(describe_entry(site, entry, show))

    if copy:
        copy_or_warn(entry['password'], "Password")


@cli.command('list')
@click.option('--filter', '-f', 'filter_text', help='Filter sites by search term')
@click.option('--verbose', '-v', is_flag=True, help='Show created date and notes')
@click.option('--sort', '-s', type=click.Choice(['site', 'username', 'modified', 'strength']),
              default='site', help='Sort by column')
@click.option('--weak-only', '-w', is_flag=True, help='Show only weak passwords')
@click.option('--json', 'as_json', is_flag=True, help='Print entries (without passwords) as JSON')
@with_vault
def list_entries(pm, filter_text, verbose, sort, weak_only, as_json):
    """List all stored passwords in a table"""
    analyzer = PasswordStrength()
    sites = pm.search_sites(filter_text) if filter_text else pm.list_sites()

    rows = []
    for site in sites:
        entry = pm.get_password(site)
        score = analyzer.analyze(entry['password'])['score']
        if weak_only and score >= 60:
            continue
        rows.append((site, entry, score, ui.age_in_days(entry.get('modified'))))

    sort_keys = {
        'site': lambda r: r[0].lower(),
        'username': lambda r: r[1].get('username', '').lower(),
        'modified': lambda r: r[3] if r[3] is not None else 10 ** 6,
        'strength': lambda r: r[2],
    }
    rows.sort(key=sort_keys[sort])

    if as_json:
        ui.print_json([dict(ui.entry_json(site, entry, False), strength=score) for site, entry, score, _ in rows])
        return

    if not rows:
        ui.info("No weak passwords found." if weak_only else
                "No entries match." if filter_text else "Your vault is empty. Add an entry with 'vk add'.")
        return

    table = ui.new_table("Site", "Username", "Strength", "Modified")
    if verbose:
        table.add_column("Created")
        table.add_column("Notes", max_width=40, overflow="ellipsis")
    for site, entry, score, age in rows:
        row = [f"[bold]{user(site)}[/]", user(entry.get('username', '')), ui.strength_text(score), ui.format_age(age)]
        if verbose:
            row += [entry.get('created', '')[:10], user(entry.get('notes', ''))]
        table.add_row(*row)
    ui.console.print(table)

    weak = sum(1 for r in rows if r[2] < 60)
    summary = f"{len(rows)} entr{'y' if len(rows) == 1 else 'ies'}"
    if weak and not weak_only:
        summary += f" · [yellow]{weak} weak[/] (vk list --weak-only)"
    ui.err_console.print(summary)


@cli.command()
@click.argument('query', required=False, default='')
@click.option('--type', '-t', 'kind', type=click.Choice(['all', 'weak', 'strong', 'old', 'recent']),
              default='all', help='Filter by type')
@click.option('--show-passwords', '-p', is_flag=True, help='Show passwords in results')
@click.option('--json', 'as_json', is_flag=True, help='Print results as JSON')
@with_vault
def search(pm, query, kind, show_passwords, as_json):
    """Search passwords by site, username, or notes

    Without QUERY, every entry is searched, e.g. 'vk search --type weak'.
    """
    analyzer = PasswordStrength()
    needle = query.lower()
    results = []

    for site in pm.list_sites():
        entry = pm.get_password(site)
        haystack = (site, entry.get('username', ''), entry.get('notes', ''))
        if not any(needle in field.lower() for field in haystack):
            continue

        score = analyzer.analyze(entry['password'])['score']
        age = ui.age_in_days(entry.get('modified'))
        if ((kind == 'weak' and score >= 60) or (kind == 'strong' and score < 60)
                or (kind == 'old' and (age is None or age < ui.OLD_AFTER_DAYS))
                or (kind == 'recent' and (age is None or age > 30))):
            continue
        results.append((site, entry, score, age))

    # Entries whose name matches come first
    results.sort(key=lambda r: (needle not in r[0].lower(), r[0].lower()))

    if as_json:
        ui.print_json([dict(ui.entry_json(site, entry, show_passwords), strength=score)
                       for site, entry, score, _ in results])
        return

    if not results:
        ui.info(f"Nothing matches '{user(query)}'" if query else "No entries match")
        return

    table = ui.new_table("Site", "Username", "Strength", "Modified")
    if show_passwords:
        table.add_column("Password")
    for site, entry, score, age in results:
        row = [f"[bold]{user(site)}[/]", user(entry.get('username', '')), ui.strength_text(score), ui.format_age(age)]
        if show_passwords:
            row.append(f"[yellow]{user(entry['password'])}[/]")
        table.add_row(*row)
    ui.console.print(table)
    ui.err_console.print(f"{len(results)} result(s)" + (f" · filtered by {kind}" if kind != 'all' else ""))


@cli.command()
@SITE_ARGUMENT()
@click.option('--timeout', '-t', default=30, type=click.IntRange(min=0), help="Clear clipboard after N seconds (0 = don't clear)")
@click.option('--username', '-u', 'copy_username', is_flag=True, help='Copy the username instead of the password')
@with_vault
def cp(pm, site, timeout, copy_username):
    """Copy password to clipboard without displaying it"""
    site = resolve_site(pm, site)
    entry = pm.get_password(site)
    if copy_username:
        copy_or_warn(entry.get('username', ''), f"Username for [bold]{user(site)}[/]", timeout)
    else:
        copy_or_warn(entry['password'], f"Password for [bold]{user(site)}[/]", timeout)


@cli.command()
@SITE_ARGUMENT()
@click.option('--username', '-u', help='New username')
@click.option('--password', '-p', 'change_password', is_flag=True, help='Enter a new password (prompted)')
@click.option('--generate', '-g', is_flag=True, help='Generate a new password')
@click.option('--length', '-l', default=16, type=click.IntRange(4, 256), help='Generated password length')
@click.option('--notes', '-n', help='New notes')
@with_vault
def edit(pm, site, username, change_password, generate, length, notes):
    """Change an entry's username, password or notes

    Without options, you are asked for each field. The old password is kept in
    the entry's history.

    Examples:
        vk edit github.com -g          # Generate a new password
        vk edit github.com -u newname  # Change the username
    """
    site = resolve_site(pm, site)
    entry = pm.get_password(site)
    new_password = None

    if username is None and notes is None and not change_password and not generate:
        username = click.prompt("Username", default=entry.get('username', ''), err=True)
        notes = click.prompt("Notes", default=entry.get('notes', ''), show_default=bool(entry.get('notes')), err=True)
        change_password = click.confirm("Change the password?", default=False, err=True)
        if change_password:
            generate = click.confirm("Generate a new one?", default=True, err=True)
            change_password = not generate

    if change_password:
        new_password = getpass.getpass("New password: ")
        if not new_password:
            ui.fail("The password must not be empty")
        if getpass.getpass("Confirm new password: ") != new_password:
            ui.fail("Passwords don't match")
        if pm.check_password_reuse(site, new_password):
            ui.warning("You have used this password for this entry before.")

    pm.update_password(site, new_password=new_password, new_username=username, new_notes=notes,
                       generate_new=generate, password_length=length)
    if generate:
        ui.console.print(f"New password: [bold green]{user(pm.get_password(site)['password'])}[/]")
    ui.success(f"Updated [bold]{user(site)}[/]")


@cli.command()
@SITE_ARGUMENT()
@click.argument('new_name')
@with_vault
def rename(pm, site, new_name):
    """Rename an entry (its password and history are kept)"""
    site = resolve_site(pm, site)
    pm.rename_entry(site, new_name)
    ui.success(f"Renamed [bold]{user(site)}[/] to [bold]{user(new_name)}[/]")


@cli.command()
@SITE_ARGUMENT()
@click.option('--show', '-S', is_flag=True, help='Show the old passwords')
@click.option('--clear', is_flag=True, help="Delete this entry's password history")
@with_vault
def history(pm, site, show, clear):
    """Show an entry's previous passwords"""
    site = resolve_site(pm, site)

    if clear:
        if click.confirm(f"Delete the password history of {site}?", default=False, err=True):
            ui.success(f"Deleted {pm.clear_history(site)} old password(s)")
        return

    entries = pm.get_password_history(site)
    if not entries:
        ui.info(f"{user(site)} has no previous passwords")
        return

    table = ui.new_table("#", "Password", "In use from", "Replaced", title=f"Password history of {user(site)}")
    for number, item in enumerate(reversed(entries), 1):
        table.add_row(str(number), f"[yellow]{user(item['password'])}[/]" if show else ui.MASK,
                      item.get('changed', '')[:10], item.get('retired', '')[:10])
    ui.console.print(table)


@cli.command()
@SITE_ARGUMENT()
@click.option('--force', '-f', is_flag=True, help='Skip confirmation prompt')
@with_vault
def delete(pm, site, force):
    """Delete a password from the vault

    Example:
        vk delete github
        vk delete github -f    # Skip confirmation
    """
    if not pm.get_password(site):
        ui.fail(f"No entry named '{user(site)}'")

    if force or click.confirm(f"Delete {site}? This cannot be undone", default=False, err=True):
        pm.delete_password(site)
        ui.success(f"Deleted [bold]{user(site)}[/]")
    else:
        ui.info("Nothing deleted")


@cli.command()
@click.option('--length', '-l', default=16, type=click.IntRange(1, 1024), help='Password length')
@click.option('--count', '-c', default=1, type=click.IntRange(1, 1000), help='Number of passwords to generate')
@click.option('--no-symbols', is_flag=True, help='Exclude symbols')
@click.option('--no-digits', is_flag=True, help='Exclude numbers')
@click.option('--no-uppercase', is_flag=True, help='Exclude uppercase letters')
@click.option('--no-ambiguous', is_flag=True, help='Exclude look-alike characters (0 O 1 l I | `)')
@click.option('--copy', '-C', is_flag=True, help='Copy the (first) password to the clipboard')
@click.option('--json', 'as_json', is_flag=True, help='Print the passwords as a JSON list')
def generate(length, count, no_symbols, no_digits, no_uppercase, no_ambiguous, copy, as_json):
    """Generate secure passwords without saving them"""
    try:
        passwords = [
            generate_password(
                length=length,
                use_symbols=not no_symbols,
                use_digits=not no_digits,
                use_uppercase=not no_uppercase,
                exclude_ambiguous=no_ambiguous
            )
            for _ in range(count)
        ]
    except ValueError as e:
        ui.fail(str(e))

    if as_json:
        ui.print_json(passwords)
    else:
        for password in passwords:
            ui.console.print(f"[bold green]{user(password)}[/]")

    if copy:
        copy_or_warn(passwords[0], "Password")


@cli.command('import-passwords')
@click.argument('file', type=click.Path(exists=True, dir_okay=False))
@click.option('--format', '-f', 'file_format',
              type=click.Choice(['csv', 'json', 'lastpass', 'bitwarden', '1password', 'chrome', 'keepass']),
              default='csv', help='Import format')
@with_vault
def import_passwords(pm, file, file_format):
    """Import passwords from file

    Example:
        vk import-passwords ~/Downloads/passwords.csv --format csv
        vk import-passwords ~/Downloads/lastpass_export.csv --format lastpass
    """
    passwords = VaultImporter().import_file(file, file_format)
    imported, skipped = pm.import_entries(passwords)

    ui.success(f"Imported {len(imported)} entr{'y' if len(imported) == 1 else 'ies'}")
    if skipped:
        ui.warning(f"Skipped {len(skipped)} that already exist: {user(', '.join(skipped[:10]))}"
                   + (" …" if len(skipped) > 10 else ""))


@cli.command('export-passwords')
@click.option('--format', '-f', 'file_format', type=click.Choice(['csv', 'json']), default='csv', help='Export format')
@click.option('--output', '-o', help='Output file path')
@click.option('--include-passwords', is_flag=True, help='Include actual passwords (CAREFUL!)')
@with_vault
def export_passwords(pm, file_format, output, include_passwords):
    """Export passwords to file

    Example:
        vk export-passwords --format csv
        vk export-passwords --format json --output backup.json --include-passwords
    """
    sites = pm.list_sites()
    if not sites:
        ui.info("Nothing to export")
        return

    export_data = {}
    for site in sites:
        entry = pm.get_password(site)
        export_data[site] = dict(entry) if include_passwords else {
            'username': entry.get('username', ''),
            'notes': entry.get('notes', ''),
            'password': '***HIDDEN***',
            'created': entry.get('created', ''),
            'modified': entry.get('modified', '')
        }

    filename = output or f"vaultkey_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_format}"
    VaultExporter().export_passwords(export_data, file_format, filename)

    ui.success(f"Exported {len(export_data)} entries to {user(filename)}")
    if include_passwords:
        ui.warning("This file contains your passwords unencrypted. Delete it as soon as you're done.")
    else:
        ui.info("Passwords were left out; add --include-passwords to include them.")


@cli.command()
@click.option('--breaches', '-b', is_flag=True, help='Check passwords against known breaches')
@click.option('--verbose', '-v', is_flag=True, help='Show the reasons behind each weak score')
@click.option('--weak-only', '-w', is_flag=True, help='Only show weak passwords (score < 60)')
@click.option('--old-only', '-o', is_flag=True, help='Only show passwords older than 90 days')
@click.option('--json', 'as_json', is_flag=True, help='Print the results as JSON')
@with_vault
def audit(pm, breaches, verbose, weak_only, old_only, as_json):
    """Perform a comprehensive security audit of all passwords

    Examples:
        vk audit                    # Basic strength audit
        vk audit -b                 # Include breach checking
        vk audit -w                 # Only show weak passwords
    """
    sites = pm.list_sites()
    if not sites:
        ui.info("No passwords to audit")
        return

    analyzer = PasswordStrength()
    checker = BreachChecker() if breaches else None
    sites_by_password: Dict[str, List[str]] = {}
    results = []
    breach_errors = 0

    with ui.err_console.status("Auditing and checking breaches…" if breaches else "Auditing…"):
        for site in sites:
            entry = pm.get_password(site)
            analysis = analyzer.analyze(entry['password'])
            fingerprint = hashlib.sha256(entry['password'].encode()).hexdigest()
            age = ui.age_in_days(entry.get('modified'))
            breach_count = 0
            if checker:
                result = checker.check_password(entry['password'])
                breach_errors += bool(result['error'])
                breach_count = result['count']

            results.append({
                'site': site,
                'username': entry.get('username', ''),
                'score': analysis['score'],
                'feedback': analysis['feedback'],
                'age_days': age,
                'old': age is not None and age > ui.OLD_AFTER_DAYS,
                'reused_with': [],
                'breach_count': breach_count,
            })
            sites_by_password.setdefault(fingerprint, []).append(site)
    
    # Every entry that shares its password lists the others
    for r in results:
        group = next(g for g in sites_by_password.values() if r['site'] in g)
        r['reused_with'] = [other for other in group if other != r['site']]

    total = len(results)
    stats = {
        'total': total,
        'strong': sum(r['score'] >= 60 for r in results),
        'weak': sum(40 <= r['score'] < 60 for r in results),
        'very_weak': sum(r['score'] < 40 for r in results),
        'old': sum(r['old'] for r in results),
        'reused': sum(bool(r['reused_with']) for r in results),
        'breached': sum(r['breach_count'] > 0 for r in results),
        'breach_errors': breach_errors,
    }
    score = stats['strong'] / total * 100
    if stats['breached']:
        score -= 30
    if stats['reused']:
        score -= 10
    stats['security_score'] = round(max(0.0, score), 1)

    shown = [r for r in results
             if not (weak_only and r['score'] >= 60) and not (old_only and not r['old'])]

    if as_json:
        ui.print_json({'summary': stats, 'entries': shown})
        return

    table = ui.new_table("Site", "Username", "Strength", "Age", "Issues")
    for r in shown:
        issues = []
        if r['breach_count']:
            issues.append(f"[bold red]breached ({r['breach_count']:,}×)[/]")
        if r['reused_with']:
            issues.append(f"[yellow]same as {user(', '.join(r['reused_with']))}[/]")
        if r['old']:
            issues.append("[yellow]old[/]")
        if verbose and r['score'] < 60 and r['feedback']:
            issues.append(f"[dim]{user('; '.join(r['feedback']))}[/]")
        table.add_row(f"[bold]{user(r['site'])}[/]", user(r['username']), ui.strength_text(r['score']),
                      ui.format_age(r['age_days']), ", ".join(issues) or "[green]—[/]")
    if shown:
        ui.console.print(table)
        ui.console.print()

    def pct(n):
        return f"{n} ({n / total * 100:.0f}%)"

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column()
    summary.add_row("Entries", str(total))
    summary.add_row("Strong or good", pct(stats['strong']))
    summary.add_row("Weak", pct(stats['weak']))
    summary.add_row("Very weak", pct(stats['very_weak']))
    summary.add_row("Reused", pct(stats['reused']))
    summary.add_row(f"Older than {ui.OLD_AFTER_DAYS} days", pct(stats['old']))
    if breaches:
        summary.add_row("Breached", pct(stats['breached']))
    colour = "green" if stats['security_score'] >= 75 else "yellow" if stats['security_score'] >= 50 else "red"
    summary.add_row("Security score", f"[bold {colour}]{stats['security_score']:.0f}/100[/]")
    ui.console.print(summary)

    ui.console.print()
    if breach_errors:
        ui.error(f"Breach check failed for {breach_errors} password(s); check your internet connection")

    todo = []
    if stats['breached']:
        todo.append(f"Change the {stats['breached']} breached password(s) first")
    if stats['very_weak'] or stats['weak']:
        todo.append(f"Replace {stats['very_weak'] + stats['weak']} weak password(s): vk edit <site> -g")
    if stats['reused']:
        todo.append(f"Give each of the {stats['reused']} entries sharing a password its own: vk edit <site> -g")
    if stats['old']:
        todo.append(f"Consider updating {stats['old']} old password(s)")
    if not breaches:
        todo.append("Check for breached passwords with 'vk audit -b'")
    for item in todo:
        ui.info(item)


@cli.command()
@click.option('--site', '-s', shell_complete=complete_site, help='Check specific site only')
@click.option('--verbose', '-v', is_flag=True, help='Also list the entries that are clean')
@with_vault
def breaches(pm, site, verbose):
    """Check passwords against known data breaches using HaveIBeenPwned

    Only the first 5 characters of each password's SHA-1 hash are sent.

    Examples:
        vk breaches                    # Check all passwords
        vk breaches -s github.com      # Check specific site
    """
    sites = [resolve_site(pm, site)] if site else pm.list_sites()
    if not sites:
        ui.info("No passwords to check")
        return

    checker = BreachChecker()
    breached, clean, failed = [], [], []
    with ui.err_console.status(f"Checking {len(sites)} password(s) with HaveIBeenPwned…"):
        for name in sites:
            result = checker.check_password(pm.get_password(name)['password'])
            if result['error']:
                failed.append((name, result['message']))
            elif result['count'] > 0:
                breached.append((name, result))
            else:
                clean.append(name)

    if breached:
        table = ui.new_table("Site", "Seen in breaches", "Severity", title="Breached passwords")
        for name, result in sorted(breached, key=lambda b: -b[1]['count']):
            table.add_row(f"[bold red]{user(name)}[/]", f"{result['count']:,}", result['severity'])
        ui.console.print(table)
    if verbose and clean:
        ui.console.print("[green]Not found in breaches:[/] " + ", ".join(user(name) for name in clean))
    for name, message in failed:
        ui.error(f"Could not check {user(name)}: {user(message)}")

    if len(failed) == len(sites):
        ui.fail("Breach check failed - make sure you have an internet connection")

    ui.err_console.print(f"Checked {len(sites) - len(failed)} · [red]{len(breached)} breached[/] · "
                         f"[green]{len(clean)} clean[/]" + (f" · {len(failed)} failed" if failed else ""))
    if breached:
        ui.warning("Change breached passwords now: vk edit <site> -g")
    elif not failed:
        ui.success("None of your passwords were found in known breaches.")


@cli.command()
@click.option('--password', '-p', help='Backup password (avoid: it ends up in your shell history)')
@click.option('--output', '-o', help='Backup file path (default: auto-generate)')
def backup(password, output):
    """Create secure encrypted backup of your vault"""
    pm = get_password_manager()
    master_password = open_vault(pm)

    try:
        backup_password = password
        if not backup_password:
            if master_password and click.confirm("Protect the backup with your master password?", default=True, err=True):
                backup_password = master_password
            else:
                ui.info("Choose a password for the backup.")
                backup_password = getpass.getpass("Backup password: ")
                if not backup_password or getpass.getpass("Confirm backup password: ") != backup_password:
                    ui.fail("Backup passwords are empty or don't match")

        backup_path = pm.create_secure_backup(backup_password, output)
        ui.success(f"Backup created: {user(backup_path)}")
        ui.info("This one file is all you need to restore. Keep it somewhere other than this computer.")
    except (VaultError, ValueError, OSError) as e:
        ui.fail(f"Backup failed: {user(e)}")
    finally:
        pm.lock()


@cli.command()
@click.argument('backup_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--password', '-p', help='Backup password (avoid: it ends up in your shell history)')
def restore(backup_file, password):
    """Restore vault from secure backup"""
    pm = get_password_manager()

    if pm.storage.exists():
        ui.warning("This replaces everything in your current vault with the backup.")
        if not click.confirm("Continue?", default=False, err=True):
            return

    backup_password = password or getpass.getpass("Backup password: ")
    if not backup_password:
        ui.fail("Restore cancelled")

    # Unlock the current vault (if any): the restored data keeps its master password
    master_password = None
    if pm.storage.exists():
        open_vault(pm)
    else:
        ui.info("Choose a master password for the restored vault.")
        master_password = prompt_new_master_password()
        if not master_password:
            ui.fail("Restore cancelled")

    try:
        backup_date = pm.restore_from_backup(backup_file, backup_password, master_password)
        ui.success(f"Vault restored from the backup made on {user(backup_date[:10])}")
    except Exception as e:
        ui.fail(f"Restore failed: {user(e)}")
    finally:
        if pm.unlocked:
            pm.lock()


@cli.command()
def passwd():
    """Change the master password"""
    pm = get_password_manager()
    if not pm.storage.exists():
        ui.fail(f"No vault found at {user(pm.storage.filename)}. Create one with 'vk init'.")
    current = unlock_with_password(pm)

    try:
        ui.info("Choose a new master password.")
        new_password = prompt_new_master_password()
        if not new_password:
            sys.exit(1)

        pm.change_master_password(current, new_password)
        end_session(pm.storage.filename)
        ui.success("Master password changed")
        ui.info("Existing backups keep the password they were created with. Any 'vk unlock' session has ended.")
    except (VaultError, ValueError, OSError) as e:
        ui.fail(f"Could not change the master password: {user(e)}")
    finally:
        pm.lock()


def _shell_export(token: str, shell: str) -> str:
    if shell == 'fish':
        return f'set -gx {SESSION_ENV} "{token}"'
    if shell == 'powershell':
        return f'$env:{SESSION_ENV}="{token}"'
    if shell == 'cmd':
        return f'set {SESSION_ENV}={token}'
    return f'export {SESSION_ENV}="{token}"'


def _default_shell() -> str:
    if os.name == 'nt':
        return 'powershell'
    return 'fish' if os.environ.get('SHELL', '').endswith('fish') else 'posix'


@cli.command()
@click.option('--timeout', '-t', default=DEFAULT_TIMEOUT_MINUTES, type=click.IntRange(1, 24 * 60),
              help='Lock again after this many minutes without use', show_default=True)
@click.option('--shell', type=click.Choice(['posix', 'fish', 'powershell', 'cmd']),
              help='Shell syntax for the export line (default: detected)')
def unlock(timeout, shell):
    """Stay unlocked between commands

    Prints a line that sets VAULTKEY_SESSION. Run it, or let your shell do it:

        eval "$(vk unlock)"

    While the session lasts, commands (and tab-completion of entry names) work
    without the master password. 'vk lock' ends it.
    """
    pm = get_password_manager()
    if not pm.storage.exists():
        ui.fail(f"No vault found at {user(pm.storage.filename)}. Create one with 'vk init'.")
    unlock_with_password(pm)
    try:
        token = start_session(pm.crypto, pm.storage.filename, timeout)
    finally:
        pm.lock()

    shell = shell or _default_shell()
    click.echo(_shell_export(token, shell))
    ui.success(f"Unlocked. Locks again after {timeout} idle minute(s), or with 'vk lock'.")
    if sys.stdout.isatty():
        hint = 'eval "$(vk unlock)"' if shell in ('posix', 'fish') else 'the line above'
        ui.info(f"Run the line above to use the session in this shell (next time: {hint})")


@cli.command()
def lock():
    """End the 'vk unlock' session"""
    if end_session(get_password_manager().storage.filename):
        ui.success("Vault locked. The session token no longer works in any shell.")
    else:
        ui.info("The vault wasn't unlocked")


@cli.command()
def status():
    """Show where the vault is and whether a session is active"""
    pm = get_password_manager()
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Version", __version__)
    grid.add_row("Vault", user(pm.storage.filename))

    info = pm.storage.get_file_info()
    if info:
        modified = datetime.fromtimestamp(info['modified']).strftime('%Y-%m-%d %H:%M')
        grid.add_row("File", f"{info['size']:,} bytes · modified {modified} · permissions {info['permissions']}")
        expires = session_expiry(pm.storage.filename)
        if expires:
            minutes = max(1, int((expires - datetime.now().timestamp()) // 60))
            grid.add_row("Session", f"[green]unlocked[/] · locks after {minutes} more minute(s) without use")
        else:
            grid.add_row("Session", "locked")
    else:
        grid.add_row("State", "[yellow]no vault yet[/] · create one with 'vk init'")
    ui.console.print(grid)


@cli.command()
@click.argument('shell', type=click.Choice(['bash', 'zsh', 'fish']))
def completion(shell):
    """Print a shell completion script

    Entry names complete while a 'vk unlock' session is active. Add to your shell profile:

        eval "$(vk completion zsh)"      # ~/.zshrc
        eval "$(vk completion bash)"     # ~/.bashrc
        vk completion fish | source      # ~/.config/fish/config.fish
    """
    prog_name = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "vk"
    if prog_name not in ("vk", "vaultkey"):
        prog_name = "vk"
    complete_var = f"_{prog_name.upper()}_COMPLETE"
    click.echo(get_completion_class(shell)(cli, {}, prog_name, complete_var).source())


@cli.command()
@click.option('--lock-after', default=5, type=click.IntRange(min=0), show_default=True,
              help='Lock after this many idle minutes (0 = never)')
def interactive(lock_after):
    """Open the full-screen app (also what 'vk' on its own does)"""
    from .app import run_app

    run_app(get_password_manager(), lock_after)


@cli.command()
def version():
    """Show VaultKey version and info"""
    ui.console.print(f"[bold]VaultKey[/] {__version__} · by {__author__} · MIT License")
    ui.console.print(f"Vault: {user(get_password_manager().storage.filename)}")
    ui.console.print("Help: vk --help · https://github.com/dhruvkulkarni02/vaultkey")


@cli.command('_clear-clipboard', hidden=True)
def clear_clipboard_helper():
    """Internal: clears the clipboard for secure_clipboard_copy()"""
    run_clearer()


# Entry point
if __name__ == '__main__':
    cli()
