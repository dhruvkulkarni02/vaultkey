"""
app.py - Full-screen terminal app (`vk` or `vk interactive`), built with Textual

Entry list on the left, details on the right, live search, keyboard shortcuts,
and dialogs for everything else. Locks itself after a few idle minutes.
"""
import hashlib
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Checkbox, DataTable, Footer, Input, Label, Select, Static

from . import __version__, ui
from .clipboard import copy_with_autoclear
from .errors import VaultError
from .generator import generate_password
from .manager import PasswordManager
from .portability import VaultExporter, VaultImporter
from .session import end_session, resume_session
from .strength import PasswordStrength

CLIPBOARD_TIMEOUT = 30
DEFAULT_LOCK_MINUTES = 5
REVEAL_SECONDS = 30
_analyzer = PasswordStrength()

_LOGO_LETTERS = [
    ("╦  ╦", "╚╗╔╝", " ╚╝ "),  # V
    ("┌─┐", "├─┤", "┴ ┴"),     # A
    ("┬ ┬", "│ │", "└─┘"),     # U
    ("┬  ", "│  ", "┴─┘"),     # L
    ("┌┬┐", " │ ", " ┴ "),     # T
    ("╦╔═", "╠╩╗", "╩ ╩"),     # K
    ("┌─┐", "├┤ ", "└─┘"),     # E
    ("┬ ┬", "└┬┘", " ┴ "),     # Y
]
LOGO = "\n".join("".join(letter[row] for letter in _LOGO_LETTERS) for row in range(3))


# --- Vault analysis -------------------------------------------------------------

@dataclass
class EntryInfo:
    site: str
    username: str
    score: int
    age_days: Optional[int]
    reused_with: List[str] = field(default_factory=list)

    @property
    def old(self) -> bool:
        return self.age_days is not None and self.age_days > ui.OLD_AFTER_DAYS

    @property
    def issues(self) -> List[str]:
        return [name for name, present in (("weak", self.score < 60), ("reused", bool(self.reused_with)),
                                            ("old", self.old)) if present]


def analyze_vault(pm: PasswordManager) -> Dict[str, EntryInfo]:
    """Strength, age and password reuse for every entry"""
    infos: Dict[str, EntryInfo] = {}
    sites_by_password: Dict[str, List[str]] = {}
    for site in pm.list_sites():
        entry = pm.get_password(site)
        infos[site] = EntryInfo(site, entry.get("username", ""), _analyzer.analyze(entry["password"])["score"],
                                ui.age_in_days(entry.get("modified")))
        fingerprint = hashlib.sha256(entry["password"].encode()).hexdigest()
        sites_by_password.setdefault(fingerprint, []).append(site)
    for group in sites_by_password.values():
        if len(group) > 1:
            for site in group:
                infos[site].reused_with = [other for other in group if other != site]
    return infos


ISSUE_STYLES = {"weak": "bold red", "reused": "bold yellow", "old": "yellow"}


def strength_meter(score: int, width: int = 18) -> Text:
    label, colour = ui.strength_label(score)
    filled = max(1, round(score / 100 * width))
    text = Text()
    text.append("━" * filled, style=colour)
    text.append("━" * (width - filled), style="grey35")
    text.append(f"  {label} ", style=f"bold {colour}")
    text.append(f"{score}/100", style="dim")
    return text


def issue_badges(info: EntryInfo) -> Text:
    text = Text()
    for issue in info.issues:
        text.append(f" {issue.upper()} ", style=f"{ISSUE_STYLES[issue]} reverse")
        text.append(" ")
    return text


def copy_text(app: App, text: str, what: str) -> None:
    try:
        copied = copy_with_autoclear(text, CLIPBOARD_TIMEOUT)
    except Exception:
        copied = False
    if copied:
        app.notify(f"{what} copied · clears in {CLIPBOARD_TIMEOUT}s", title="Clipboard")
    else:
        app.notify("Install pyperclip (and xclip or wl-clipboard on Linux) to use the clipboard.",
                   title="Clipboard not available", severity="error")


def password_feedback(password: str) -> Text:
    return strength_meter(_analyzer.analyze(password)["score"]) if password else Text("")


def short_path(path: str, limit: int = 48) -> str:
    """Path with ~ for the home directory, shortened in the middle if long"""
    home = os.path.expanduser("~")
    if path.startswith(home + os.sep):
        path = "~" + path[len(home):]
    return path if len(path) <= limit else path[:16] + "…" + path[-(limit - 17):]


def is_weak_master_password(password: str) -> bool:
    return len(password) < 12 or _analyzer.analyze(password)["score"] < 60


# --- Unlocking --------------------------------------------------------------------

class UnlockScreen(Screen):
    """Master password prompt"""

    BINDINGS = [Binding("ctrl+q", "app.quit", "Quit")]

    def __init__(self, message: str = ""):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="card"):
            yield Static(LOGO, id="logo")
            yield Static(f"v{__version__}\n{short_path(self.app.pm.storage.filename)}", classes="subtitle",
                         markup=False)
            yield Input(password=True, placeholder="Master password", id="password")
            yield Static(self.message, id="message", markup=False)
            yield Static("Enter to unlock · Ctrl+Q to quit", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#password", Input).focus()

    @on(Input.Submitted, "#password")
    def submitted(self, event: Input.Submitted) -> None:
        if not event.value:
            return
        event.input.disabled = True
        self.query_one("#message", Static).update(Text("Unlocking…", style="dim"))
        self.unlock(event.value)

    @work(thread=True, exclusive=True)
    def unlock(self, password: str) -> None:
        try:
            unlocked = self.app.pm.unlock(password)
            error = "" if unlocked else "Wrong master password"
        except VaultError as e:
            unlocked, error = False, str(e)
        self.app.call_from_thread(self.finished, unlocked, error)

    def finished(self, unlocked: bool, error: str) -> None:
        if unlocked:
            self.app.show_vault()
            if self.app.pm.migrated_from_version:
                self.app.notify("Your vault was upgraded to the new format. If old copies of the vault file may "
                                "exist, change your master password (press p).", severity="warning", timeout=12)
            return
        password_input = self.query_one("#password", Input)
        password_input.disabled = False
        password_input.value = ""
        password_input.focus()
        self.query_one("#message", Static).update(Text(error, style="bold red"))


class CreateVaultScreen(Screen):
    """First run: choose a master password"""

    BINDINGS = [Binding("ctrl+q", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        with Vertical(id="card"):
            yield Static(LOGO, id="logo")
            yield Static("Welcome! Choose a master password for your new vault.", classes="subtitle")
            yield Input(password=True, placeholder="Master password", id="password")
            yield Static(id="strength")
            yield Input(password=True, placeholder="Confirm master password", id="confirm")
            yield Checkbox("Use it even though it's weak", id="accept-weak", classes="hidden")
            yield Static(id="message")
            yield Button("Create vault", variant="primary", id="create")
            yield Static("It protects everything and cannot be recovered if you forget it.\n"
                         "A passphrase of four or more random words is strong and memorable.", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#password", Input).focus()

    @on(Input.Changed, "#password")
    def update_strength(self, event: Input.Changed) -> None:
        self.query_one("#strength", Static).update(password_feedback(event.value))
        self.query_one("#accept-weak").set_class(not (event.value and is_weak_master_password(event.value)), "hidden")

    @on(Input.Submitted)
    def next_field(self, event: Input.Submitted) -> None:
        if event.input.id == "password":
            self.query_one("#confirm", Input).focus()
        else:
            self.create()

    @on(Button.Pressed, "#create")
    def create(self) -> None:
        password = self.query_one("#password", Input).value
        message = self.query_one("#message", Static)
        if not password:
            message.update(Text("Enter a master password", style="bold red"))
        elif password != self.query_one("#confirm", Input).value:
            message.update(Text("The passwords don't match", style="bold red"))
        elif is_weak_master_password(password) and not self.query_one("#accept-weak", Checkbox).value:
            message.update(Text("This password is weak. Choose a stronger one, or tick the box to use it anyway.",
                                style="bold yellow"))
        else:
            message.update(Text("Creating your vault…", style="dim"))
            self.query_one("#create", Button).disabled = True
            self.create_vault(password)

    @work(thread=True, exclusive=True)
    def create_vault(self, password: str) -> None:
        try:
            self.app.pm.create_vault(password)
            self.app.call_from_thread(self.app.show_vault)
        except (VaultError, ValueError, OSError) as e:
            self.app.call_from_thread(self.failed, str(e))

    def failed(self, error: str) -> None:
        self.query_one("#create", Button).disabled = False
        self.query_one("#message", Static).update(Text(error, style="bold red"))


# --- Main screen ------------------------------------------------------------------

class VaultScreen(Screen):
    """Entry list, details and every action"""

    BINDINGS = [
        Binding("slash", "focus_search", "Search"),
        Binding("n", "new", "New"),
        Binding("e", "edit", "Edit"),
        Binding("c", "copy_password", "Copy"),
        Binding("u", "copy_username", "User"),
        Binding("r", "reveal", "Show"),
        Binding("h", "history", "History", show=False),
        Binding("d", "delete", "Delete"),
        Binding("g", "generator", "Generate", show=False),
        Binding("f", "toggle_problems", "Problems", show=False),
        Binding("i", "import", "Import"),
        Binding("x", "export", "Export", show=False),
        Binding("b", "backup", "Backup", show=False),
        Binding("p", "change_password", "Master password", show=False),
        Binding("l", "lock", "Lock"),
        Binding("question_mark", "help", "Help"),
        Binding("escape", "clear_search", "Clear search", show=False),
        Binding("down", "focus_list", show=False),
        Binding("ctrl+q", "app.quit", "Quit", show=False),
    ]

    def __init__(self):
        super().__init__()
        self.infos: Dict[str, EntryInfo] = {}
        self.visible_sites: List[str] = []
        self.reveal = False
        self.problems_only = False
        self._hide_timer = None

    @property
    def pm(self) -> PasswordManager:
        return self.app.pm

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Static(Text.assemble(("◆ ", "bold"), ("VaultKey", "bold")), id="brand")
            yield Static(id="stats")
        yield Input(placeholder="Search entries…   ( / )", id="search")
        with Horizontal(id="main"):
            yield DataTable(id="entries", cursor_type="row", show_header=False, show_row_labels=False)
            with Vertical(id="detail"):
                yield VerticalScroll(Static(id="detail-body"))
                with Horizontal(id="actions"):
                    yield Button("Copy password", id="copy", variant="primary")
                    yield Button("Copy username", id="copy-user")
                    yield Button("Edit", id="edit")
                    yield Button("Delete", id="delete", variant="error")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#entries", DataTable)
        table.add_column(" ", key="dot", width=1)
        table.add_column("Entry", key="entry")
        table.add_column("", key="issues")
        self.refresh_entries()
        table.focus()

    # Data -------------------------------------------------------------------

    def refresh_entries(self, select: Optional[str] = None) -> None:
        table = self.query_one("#entries", DataTable)
        if select is None and self.visible_sites and table.cursor_row < len(self.visible_sites):
            select = self.visible_sites[table.cursor_row]

        self.infos = analyze_vault(self.pm)
        query = self.query_one("#search", Input).value.strip().lower()
        self.visible_sites = []
        for site in sorted(self.infos, key=str.lower):
            info = self.infos[site]
            notes = self.pm.get_password(site).get("notes", "")
            if query and not any(query in text.lower() for text in (site, info.username, notes)):
                continue
            if self.problems_only and not info.issues:
                continue
            self.visible_sites.append(site)

        table.clear()
        for site in self.visible_sites:
            info = self.infos[site]
            colour = ui.strength_label(info.score)[1]
            entry = Text(site, style="bold", no_wrap=True, overflow="ellipsis")
            entry.append("\n" + (info.username or "—"), style="dim")
            # The most important issue, and how many more there are
            issues = Text(justify="right")
            if info.issues:
                issues.append(info.issues[0], style=ISSUE_STYLES[info.issues[0]])
                if len(info.issues) > 1:
                    issues.append(f"\n+{len(info.issues) - 1} more", style="dim")
            table.add_row(Text("●", style=colour), entry, issues, key=site, height=2)
        if select in self.visible_sites:
            table.move_cursor(row=self.visible_sites.index(select))

        self.update_stats()
        self.show_detail()

    def current_site(self) -> Optional[str]:
        table = self.query_one("#entries", DataTable)
        if not self.visible_sites or table.cursor_row >= len(self.visible_sites):
            return None
        return self.visible_sites[table.cursor_row]

    def update_stats(self) -> None:
        counts = {issue: sum(issue in info.issues for info in self.infos.values()) for issue in ISSUE_STYLES}
        text = Text()
        text.append(f"{len(self.infos)} entries", style="bold")
        for issue, count in counts.items():
            if count:
                text.append("   ")
                text.append(f"{count} {issue}", style=ISSUE_STYLES[issue])
        if not any(counts.values()) and self.infos:
            text.append("   all healthy", style="green")
        if self.problems_only:
            text.append("   [showing problems only · f]", style="dim")
        if self.app.lock_after:
            text.append(f"   auto-lock {self.app.lock_after}m", style="dim")
        self.query_one("#stats", Static).update(text)

    def show_detail(self) -> None:
        body = self.query_one("#detail-body", Static)
        site = self.current_site()
        for button in self.query("#actions Button"):
            button.disabled = site is None

        if site is None:
            if not self.infos:
                body.update(Text.assemble(("Your vault is empty\n\n", "bold"),
                                          ("Press ", "dim"), ("n", "bold"), (" to add an entry, or ", "dim"),
                                          ("i", "bold"), (" to import from another password manager.", "dim")))
            else:
                body.update(Text.assemble(("Nothing matches\n\n", "bold"), ("Press ", "dim"), ("Esc", "bold"),
                                          (" to clear the search", "dim"),
                                          (" or f to show all entries" if self.problems_only else "", "dim")))
            return

        entry = self.pm.get_password(site)
        info = self.infos[site]
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", justify="right")
        grid.add_column()
        grid.add_row("Username", Text(entry.get("username", "") or "—", style="cyan"))
        grid.add_row("Password", Text(entry["password"], style="bold yellow") if self.reveal
                     else Text("•" * 12 + "   r to show", style="default"))
        grid.add_row("Strength", strength_meter(info.score))
        if entry.get("notes"):
            grid.add_row("Notes", Text(entry["notes"]))
        grid.add_row("Created", Text(entry.get("created", "")[:10] or "—"))
        grid.add_row("Modified", Text(f"{entry.get('modified', '')[:10]}  ({ui.format_age(info.age_days)})"))
        history = entry.get("history", [])
        grid.add_row("History", Text(f"{len(history)} previous password(s)" + ("   h to view" if history else "")))

        parts = [Text(site, style="bold"), Text(""), grid]
        if info.issues:
            advice = []
            if info.score < 60:
                advice.append("This password is weak.")
            if info.reused_with:
                advice.append(f"Same password as {', '.join(info.reused_with)}.")
            if info.old:
                advice.append(f"Not changed for {ui.format_age(info.age_days).replace(' ago', '')}.")
            parts += [Text(""), issue_badges(info), Text(" ".join(advice) + " Press e to change it.", style="dim")]
        body.update(Group(*parts))

    # Events -----------------------------------------------------------------

    @on(DataTable.RowHighlighted, "#entries")
    def row_changed(self) -> None:
        self.hide_password()

    @on(DataTable.RowSelected, "#entries")
    def row_selected(self) -> None:
        self.action_copy_password()

    @on(Input.Changed, "#search")
    def search_changed(self) -> None:
        self.refresh_entries()

    @on(Input.Submitted, "#search")
    def search_submitted(self) -> None:
        self.action_focus_list()

    @on(Button.Pressed, "#actions Button")
    def button_pressed(self, event: Button.Pressed) -> None:
        {"copy": self.action_copy_password, "copy-user": self.action_copy_username,
         "edit": self.action_edit, "delete": self.action_delete}[event.button.id]()

    # Actions ----------------------------------------------------------------

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_focus_list(self) -> None:
        self.query_one("#entries", DataTable).focus()

    def action_clear_search(self) -> None:
        search = self.query_one("#search", Input)
        if search.value:
            search.value = ""
        self.action_focus_list()

    def action_copy_password(self) -> None:
        site = self.current_site()
        if site:
            copy_text(self.app, self.pm.get_password(site)["password"], f"Password for {site}")

    def action_copy_username(self) -> None:
        site = self.current_site()
        if site:
            copy_text(self.app, self.pm.get_password(site).get("username", ""), f"Username for {site}")

    def action_reveal(self) -> None:
        if not self.current_site():
            return
        self.reveal = not self.reveal
        if self._hide_timer:
            self._hide_timer.stop()
        if self.reveal:
            self._hide_timer = self.set_timer(REVEAL_SECONDS, self.hide_password)
        self.show_detail()

    def hide_password(self) -> None:
        self.reveal = False
        self.show_detail()

    def action_toggle_problems(self) -> None:
        self.problems_only = not self.problems_only
        self.refresh_entries()
        if self.problems_only:
            self.notify(f"{len(self.visible_sites)} entr{'y needs' if len(self.visible_sites) == 1 else 'ies need'} attention. "
                        "Press f again to show everything.")

    def action_new(self) -> None:
        self.app.push_screen(EntryFormScreen(set(self.infos)), lambda data: self.save_entry(None, data))

    def action_edit(self) -> None:
        site = self.current_site()
        if site:
            self.app.push_screen(EntryFormScreen(set(self.infos), site, self.pm.get_password(site)),
                                 lambda data: self.save_entry(site, data))

    def save_entry(self, original: Optional[str], data: Optional[dict]) -> None:
        if not data:
            return
        site = data["site"]
        try:
            if original is None:
                self.pm.add_password(site, data["username"], data["password"], data["notes"])
            else:
                if site != original:
                    self.pm.rename_entry(original, site)
                current = self.pm.get_password(site)
                changed_password = data["password"] if data["password"] != current["password"] else None
                if changed_password and self.pm.check_password_reuse(site, changed_password):
                    self.notify("You've used this password for this entry before.", severity="warning")
                self.pm.update_password(site, new_password=changed_password,
                                        new_username=data["username"], new_notes=data["notes"])
        except (VaultError, ValueError, OSError) as e:
            self.notify(str(e), title="Not saved", severity="error")
            return
        self.refresh_entries(select=site)
        self.notify(f"Saved {site}")
        if self.infos[site].reused_with:
            self.notify(f"{site} shares its password with {', '.join(self.infos[site].reused_with)}.",
                        severity="warning")

    def action_delete(self) -> None:
        site = self.current_site()
        if not site:
            return

        def confirmed(yes: Optional[bool]) -> None:
            if yes:
                self.pm.delete_password(site)
                self.refresh_entries()
                self.notify(f"Deleted {site}")

        self.app.push_screen(ConfirmScreen(f"Delete {site}?", "Its password and history are removed for good.",
                                           "Delete"), confirmed)

    def action_history(self) -> None:
        site = self.current_site()
        if site:
            self.app.push_screen(HistoryScreen(site, self.pm.get_password_history(site)))

    def action_generator(self) -> None:
        self.app.push_screen(GeneratorScreen())

    def action_import(self) -> None:
        def imported(entries: Optional[dict]) -> None:
            if not entries:
                return
            try:
                added, skipped = self.pm.import_entries(entries)
            except (VaultError, OSError) as e:
                self.notify(str(e), title="Import failed", severity="error")
                return
            self.refresh_entries()
            self.notify(f"Imported {len(added)} entr{'y' if len(added) == 1 else 'ies'}"
                        + (f", skipped {len(skipped)} that already exist" if skipped else ""), title="Import")

        self.app.push_screen(ImportScreen(set(self.infos)), imported)

    def action_export(self) -> None:
        self.app.push_screen(ExportScreen())

    def action_backup(self) -> None:
        self.app.push_screen(BackupScreen())

    def action_change_password(self) -> None:
        self.app.push_screen(ChangePasswordScreen())

    def action_lock(self) -> None:
        self.app.lock_vault("Vault locked")

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen())


# --- Dialogs ----------------------------------------------------------------------

class Dialog(ModalScreen):
    """Base for centred dialogs; Escape closes"""

    BINDINGS = [Binding("escape", "close", "Close")]

    def action_close(self) -> None:
        self.dismiss(None)

    def show_error(self, message: str) -> None:
        self.query_one("#error", Static).update(Text(message, style="bold red"))


class ConfirmScreen(Dialog):
    BINDINGS = [Binding("y", "yes", "Yes"), Binding("n", "close", "No"), Binding("escape", "close", "Cancel")]

    def __init__(self, title: str, detail: str, confirm_label: str = "Yes"):
        super().__init__()
        self.title_text, self.detail, self.confirm_label = title, detail, confirm_label

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog narrow"):
            yield Static(self.title_text, classes="dialog-title", markup=False)
            yield Static(self.detail, markup=False)
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="no")
                yield Button(self.confirm_label, id="yes", variant="error")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    @on(Button.Pressed, "#yes")
    def action_yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def no(self) -> None:
        self.dismiss(False)


class EntryFormScreen(Dialog):
    """Add or edit an entry"""

    BINDINGS = [
        Binding("escape", "close", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
        Binding("ctrl+g", "generate", "Generate password"),
        Binding("ctrl+r", "toggle_show", "Show password"),
    ]

    def __init__(self, existing_sites: set, site: Optional[str] = None, entry: Optional[dict] = None):
        super().__init__()
        self.existing_sites = existing_sites
        self.original_site = site
        self.entry = entry or {}

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static("Edit entry" if self.original_site else "New entry", classes="dialog-title")
            yield Label("Site or service", classes="field-label")
            yield Input(self.original_site or "", placeholder="github.com", id="site")
            yield Label("Username or email", classes="field-label")
            yield Input(self.entry.get("username", ""), placeholder="you@example.com", id="username")
            yield Label("Password", classes="field-label")
            with Horizontal(classes="row"):
                yield Input(self.entry.get("password", ""), password=True, id="password")
                yield Button("Show", id="show")
                yield Button("Generate", id="generate", variant="primary")
            yield Static(password_feedback(self.entry.get("password", "")), id="strength")
            yield Label("Notes", classes="field-label")
            yield Input(self.entry.get("notes", ""), placeholder="Optional", id="notes")
            yield Static(id="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save", id="save", variant="success")
            yield Static("Ctrl+G generate · Ctrl+R show · Ctrl+S save · Esc cancel", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#username" if self.original_site else "#site", Input).focus()

    @on(Input.Changed, "#password")
    def password_changed(self, event: Input.Changed) -> None:
        self.query_one("#strength", Static).update(password_feedback(event.value))

    @on(Input.Submitted)
    def submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "notes":
            self.action_save()
        else:
            self.focus_next()

    @on(Button.Pressed, "#show")
    def action_toggle_show(self) -> None:
        password_input = self.query_one("#password", Input)
        password_input.password = not password_input.password
        self.query_one("#show", Button).label = "Show" if password_input.password else "Hide"

    @on(Button.Pressed, "#generate")
    def action_generate(self) -> None:
        def chosen(password: Optional[str]) -> None:
            if password:
                password_input = self.query_one("#password", Input)
                password_input.value = password
                if password_input.password:
                    self.action_toggle_show()

        self.app.push_screen(GeneratorScreen(pick=True), chosen)

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#save")
    def action_save(self) -> None:
        site = self.query_one("#site", Input).value.strip()
        password = self.query_one("#password", Input).value
        if not site:
            return self.show_error("Enter a site or service name")
        if site != self.original_site and site in self.existing_sites:
            return self.show_error(f"An entry named {site} already exists. Edit that one, or pick another name.")
        if not password:
            return self.show_error("Enter a password, or press Generate")
        self.dismiss({
            "site": site,
            "username": self.query_one("#username", Input).value.strip(),
            "password": password,
            "notes": self.query_one("#notes", Input).value,
        })


class GeneratorScreen(Dialog):
    """Generate passwords; with pick=True, 'Use' returns the password"""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("space", "regenerate", "New password"),
        Binding("ctrl+c", "copy", "Copy", priority=True),
    ]

    def __init__(self, pick: bool = False):
        super().__init__()
        self.pick = pick
        self.password = ""

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static("Password generator", classes="dialog-title")
            yield Static(id="generated")
            yield Static(id="strength")
            with Horizontal(classes="row options"):
                yield Label("Length", classes="inline-label")
                yield Input("20", type="integer", id="length", max_length=3)
                yield Checkbox("A-Z", True, id="uppercase")
                yield Checkbox("0-9", True, id="digits")
                yield Checkbox("!@#", True, id="symbols")
                yield Checkbox("No look-alikes", False, id="no_ambiguous")
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close")
                yield Button("New password", id="regenerate")
                yield Button("Copy", id="copy")
                if self.pick:
                    yield Button("Use this password", id="use", variant="success")
            yield Static("Space new password · Ctrl+C copy · Esc close", classes="hint")

    def on_mount(self) -> None:
        self.action_regenerate()
        self.query_one("#use" if self.pick else "#regenerate", Button).focus()

    @on(Input.Changed, "#length")
    @on(Checkbox.Changed)
    @on(Button.Pressed, "#regenerate")
    def action_regenerate(self) -> None:
        length_text = self.query_one("#length", Input).value
        length = int(length_text) if length_text.isdigit() else 0
        if not 4 <= length <= 128:
            self.query_one("#generated", Static).update(Text("Length must be 4 to 128", style="bold red"))
            return
        self.password = generate_password(
            length,
            use_uppercase=self.query_one("#uppercase", Checkbox).value,
            use_digits=self.query_one("#digits", Checkbox).value,
            use_symbols=self.query_one("#symbols", Checkbox).value,
            exclude_ambiguous=self.query_one("#no_ambiguous", Checkbox).value,
        )
        self.query_one("#generated", Static).update(Text(self.password, style="bold green"))
        self.query_one("#strength", Static).update(password_feedback(self.password))

    @on(Button.Pressed, "#copy")
    def action_copy(self) -> None:
        if self.password:
            copy_text(self.app, self.password, "Password")

    @on(Button.Pressed, "#use")
    def use(self) -> None:
        self.dismiss(self.password)

    @on(Button.Pressed, "#close")
    def close_button(self) -> None:
        self.dismiss(None)


class HistoryScreen(Dialog):
    BINDINGS = [Binding("escape", "close", "Close"), Binding("r", "reveal", "Show"), Binding("c", "copy", "Copy")]

    def __init__(self, site: str, history: List[dict]):
        super().__init__()
        self.site, self.history, self.reveal = site, list(reversed(history)), False

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Static(Text.assemble(("Password history · ", "bold"), (self.site, "bold")), classes="dialog-title")
            if self.history:
                yield DataTable(id="history", cursor_type="row")
                yield Static("r show/hide · c copy the selected password · Esc close", classes="hint")
            else:
                yield Static("No previous passwords yet. When you change this entry's password, the old one is kept here.")
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        if self.history:
            self.fill()
            self.query_one("#history", DataTable).focus()

    def fill(self) -> None:
        table = self.query_one("#history", DataTable)
        table.clear(columns=True)
        table.add_columns("#", "Password", "In use from", "Replaced")
        for number, item in enumerate(self.history, 1):
            table.add_row(str(number), Text(item["password"], style="yellow") if self.reveal else "••••••••••••",
                          item.get("changed", "")[:10], item.get("retired", "")[:10])

    def action_reveal(self) -> None:
        if self.history:
            self.reveal = not self.reveal
            row = self.query_one("#history", DataTable).cursor_row
            self.fill()
            self.query_one("#history", DataTable).move_cursor(row=row)

    def action_copy(self) -> None:
        if self.history:
            item = self.history[self.query_one("#history", DataTable).cursor_row]
            copy_text(self.app, item["password"], "Old password")

    @on(Button.Pressed, "#close")
    def close_button(self) -> None:
        self.dismiss(None)


class ImportScreen(Dialog):
    """Pick a file and format, preview, then import"""

    def __init__(self, existing_sites: set):
        super().__init__()
        self.existing_sites = existing_sites
        self.entries: Optional[dict] = None

    def compose(self) -> ComposeResult:
        formats = [(description, key) for key, description in VaultImporter.SUPPORTED_FORMATS.items()]
        with Vertical(classes="dialog"):
            yield Static("Import passwords", classes="dialog-title")
            yield Label("Exported from", classes="field-label")
            yield Select(formats, value="csv", allow_blank=False, id="format")
            yield Label("File", classes="field-label")
            yield Input(placeholder="~/Downloads/passwords.csv", id="path")
            yield Input(password=True, placeholder="Password of the encrypted export", id="file-password",
                        classes="hidden")
            yield Static(id="preview")
            yield Static(id="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Import", id="import", variant="success", disabled=True)
            yield Static("Entries that already exist in your vault are skipped. Delete the export file afterwards: "
                         "it contains your passwords unencrypted.", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#path", Input).focus()

    def path(self) -> str:
        return os.path.expanduser(self.query_one("#path", Input).value.strip())

    @on(Select.Changed, "#format")
    @on(Input.Changed, "#path")
    def update_preview(self) -> None:
        encrypted = self.query_one("#format", Select).value == "vaultkey"
        self.query_one("#file-password").set_class(not encrypted, "hidden")
        self.query_one("#error", Static).update("")
        preview = self.query_one("#preview", Static)
        self.entries = None
        path = self.path()
        if not path or not os.path.isfile(path):
            preview.update(Text("Type the path of the exported file" if not path else "File not found", style="dim"))
            self.query_one("#import", Button).disabled = True
            return
        if encrypted:
            preview.update(Text("Encrypted VaultKey export: enter its password, then Import", style="dim"))
            self.query_one("#import", Button).disabled = False
            return
        try:
            self.entries = VaultImporter().import_file(path, self.query_one("#format", Select).value)
        except Exception as e:
            preview.update(Text(f"Can't read this file as {self.query_one('#format', Select).value}: {e}",
                                style="red"))
            self.query_one("#import", Button).disabled = True
            return
        duplicates = len(set(self.entries) & self.existing_sites)
        preview.update(Text.assemble(
            (f"Found {len(self.entries)} entr{'y' if len(self.entries) == 1 else 'ies'}", "bold green"),
            (f" · {duplicates} already in your vault" if duplicates else "", "yellow")))
        self.query_one("#import", Button).disabled = not self.entries

    @on(Input.Submitted, "#path")
    @on(Input.Submitted, "#file-password")
    @on(Button.Pressed, "#import")
    def do_import(self) -> None:
        if self.query_one("#import", Button).disabled:
            return
        if self.query_one("#format", Select).value != "vaultkey":
            self.dismiss(self.entries)
            return
        password = self.query_one("#file-password", Input).value
        if not password:
            self.query_one("#file-password", Input).focus()
            return self.show_error("Enter the password of the encrypted export")
        self.query_one("#preview", Static).update(Text("Decrypting…", style="dim"))
        self.decrypt(self.path(), password)

    @work(thread=True, exclusive=True)
    def decrypt(self, path: str, password: str) -> None:
        try:
            entries = VaultImporter().import_file(path, "vaultkey", password)
            self.app.call_from_thread(self.dismiss, entries)
        except Exception as e:
            self.app.call_from_thread(self.show_error, str(e))

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.dismiss(None)


class ExportScreen(Dialog):
    FORMATS = [
        ("Encrypted VaultKey file (recommended)", "vaultkey"),
        ("CSV: spreadsheets and most password managers", "csv"),
        ("JSON", "json"),
        ("Bitwarden CSV", "bitwarden"),
        ("LastPass CSV", "lastpass"),
    ]
    EXTENSIONS = {"vaultkey": "vkexport", "csv": "csv", "json": "json", "bitwarden": "csv", "lastpass": "csv"}

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static("Export passwords", classes="dialog-title")
            yield Label("Format", classes="field-label")
            yield Select(self.FORMATS, value="vaultkey", allow_blank=False, id="format")
            yield Label("Save to", classes="field-label")
            yield Input(self.default_path("vaultkey"), id="path")
            yield Checkbox("Include passwords", False, id="include", classes="hidden")
            yield Input(password=True, placeholder="Password for the export file", id="export-password")
            yield Input(password=True, placeholder="Confirm password", id="export-confirm")
            yield Static(id="warning")
            yield Static(id="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Export", id="export", variant="success")

    @staticmethod
    def default_path(file_format: str) -> str:
        return f"~/vaultkey-export-{datetime.now().strftime('%Y%m%d')}.{ExportScreen.EXTENSIONS[file_format]}"

    @on(Select.Changed, "#format")
    def format_changed(self, event: Select.Changed) -> None:
        encrypted = event.value == "vaultkey"
        self.query_one("#path", Input).value = self.default_path(event.value)
        self.query_one("#include").set_class(encrypted, "hidden")
        for selector in ("#export-password", "#export-confirm"):
            self.query_one(selector).set_class(not encrypted, "hidden")
        self.update_warning()

    @on(Checkbox.Changed, "#include")
    def update_warning(self) -> None:
        plaintext = (self.query_one("#format", Select).value != "vaultkey"
                     and self.query_one("#include", Checkbox).value)
        self.query_one("#warning", Static).update(
            Text("This file will contain your passwords UNENCRYPTED. Delete it as soon as you've used it.",
                 style="bold red") if plaintext else "")

    @on(Button.Pressed, "#export")
    def export(self) -> None:
        file_format = self.query_one("#format", Select).value
        path = os.path.expanduser(self.query_one("#path", Input).value.strip())
        if not path:
            return self.show_error("Choose where to save the file")
        password = None
        if file_format == "vaultkey":
            password = self.query_one("#export-password", Input).value
            if not password:
                return self.show_error("Choose a password for the export file")
            if password != self.query_one("#export-confirm", Input).value:
                return self.show_error("The passwords don't match")
        self.query_one("#export", Button).disabled = True
        self.write(file_format, path, self.query_one("#include", Checkbox).value, password)

    @work(thread=True, exclusive=True)
    def write(self, file_format: str, path: str, include_passwords: bool, password: Optional[str]) -> None:
        pm = self.app.pm
        data = {}
        for site in pm.list_sites():
            entry = {k: v for k, v in pm.get_password(site).items() if k != "history"}
            if file_format != "vaultkey" and not include_passwords:
                entry["password"] = "***HIDDEN***"
            data[site] = entry
        try:
            VaultExporter().export_passwords(data, file_format, path, master_password=password)
        except Exception as e:
            self.app.call_from_thread(self.failed, str(e))
            return
        self.app.call_from_thread(self.done, path, len(data))

    def done(self, path: str, count: int) -> None:
        self.app.notify(f"Exported {count} entries to {path}", title="Export")
        self.dismiss(path)

    def failed(self, message: str) -> None:
        self.query_one("#export", Button).disabled = False
        self.show_error(message)

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.dismiss(None)


class BackupScreen(Dialog):
    def compose(self) -> ComposeResult:
        default = f"~/vaultkey_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.vkbak"
        with Vertical(classes="dialog"):
            yield Static("Create a backup", classes="dialog-title")
            yield Static("A single encrypted file with everything in your vault. Keep it somewhere other than this "
                         "computer; restore it with 'vk restore'.", classes="muted")
            yield Label("Save to", classes="field-label")
            yield Input(default, id="path")
            yield Label("Backup password (can be your master password)", classes="field-label")
            yield Input(password=True, id="password")
            yield Input(password=True, placeholder="Confirm backup password", id="confirm")
            yield Static(id="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Create backup", id="create", variant="success")

    def on_mount(self) -> None:
        self.query_one("#password", Input).focus()

    @on(Input.Submitted, "#confirm")
    @on(Button.Pressed, "#create")
    def create(self) -> None:
        path = os.path.expanduser(self.query_one("#path", Input).value.strip())
        password = self.query_one("#password", Input).value
        if not path:
            return self.show_error("Choose where to save the backup")
        if not password:
            return self.show_error("Choose a backup password")
        if password != self.query_one("#confirm", Input).value:
            return self.show_error("The passwords don't match")
        self.query_one("#create", Button).disabled = True
        self.query_one("#error", Static).update(Text("Encrypting…", style="dim"))
        self.write(path, password)

    @work(thread=True, exclusive=True)
    def write(self, path: str, password: str) -> None:
        try:
            self.app.pm.create_secure_backup(password, path)
        except (VaultError, ValueError, OSError) as e:
            self.app.call_from_thread(self.failed, str(e))
            return
        self.app.call_from_thread(self.done, path)

    def done(self, path: str) -> None:
        self.app.notify(f"Backup saved to {path}", title="Backup")
        self.dismiss(path)

    def failed(self, message: str) -> None:
        self.query_one("#create", Button).disabled = False
        self.show_error(message)

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.dismiss(None)


class ChangePasswordScreen(Dialog):
    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static("Change master password", classes="dialog-title")
            yield Input(password=True, placeholder="Current master password", id="current")
            yield Input(password=True, placeholder="New master password", id="new")
            yield Static(id="strength")
            yield Input(password=True, placeholder="Confirm new master password", id="confirm")
            yield Checkbox("Use it even though it's weak", id="accept-weak", classes="hidden")
            yield Static(id="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Change", id="change", variant="success")
            yield Static("Backups keep the password they were made with. A 'vk unlock' session ends.",
                         classes="hint")

    def on_mount(self) -> None:
        self.query_one("#current", Input).focus()

    @on(Input.Changed, "#new")
    def strength(self, event: Input.Changed) -> None:
        self.query_one("#strength", Static).update(password_feedback(event.value))
        self.query_one("#accept-weak").set_class(not (event.value and is_weak_master_password(event.value)), "hidden")

    @on(Input.Submitted)
    def submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "confirm":
            self.change()
        else:
            self.focus_next()

    @on(Button.Pressed, "#change")
    def change(self) -> None:
        current = self.query_one("#current", Input).value
        new = self.query_one("#new", Input).value
        if not current or not new:
            return self.show_error("Fill in both passwords")
        if new != self.query_one("#confirm", Input).value:
            return self.show_error("The new passwords don't match")
        if is_weak_master_password(new) and not self.query_one("#accept-weak", Checkbox).value:
            return self.show_error("The new password is weak. Choose a stronger one, or tick the box.")
        self.query_one("#change", Button).disabled = True
        self.query_one("#error", Static).update(Text("Re-encrypting…", style="dim"))
        self.run_change(current, new)

    @work(thread=True, exclusive=True)
    def run_change(self, current: str, new: str) -> None:
        try:
            changed = self.app.pm.change_master_password(current, new)
        except VaultError as e:
            self.app.call_from_thread(self.failed, str(e))
            return
        if changed:
            end_session(self.app.pm.storage.filename)
            self.app.call_from_thread(self.done)
        else:
            self.app.call_from_thread(self.failed, "The current master password is wrong")

    def done(self) -> None:
        self.app.notify("Master password changed", title="Done")
        self.dismiss(True)

    def failed(self, message: str) -> None:
        self.query_one("#change", Button).disabled = False
        self.show_error(message)

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.dismiss(None)


class HelpScreen(Dialog):
    BINDINGS = [Binding("escape", "close", "Close"), Binding("question_mark", "close", "Close")]

    KEYS = [
        ("/", "Search"), ("↑ ↓", "Move through entries"), ("Enter, c", "Copy password"), ("u", "Copy username"),
        ("r", "Show / hide password"), ("n", "New entry"), ("e", "Edit entry"), ("d", "Delete entry"),
        ("h", "Password history"), ("f", "Only entries that need attention"), ("g", "Password generator"),
        ("i", "Import"), ("x", "Export"), ("b", "Backup"), ("p", "Change master password"), ("l", "Lock"),
        ("Ctrl+P", "Command palette (change theme…)"), ("Ctrl+Q", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        keys = Table.grid(padding=(0, 3))
        keys.add_column(style="bold cyan", justify="right")
        keys.add_column()
        for key, description in self.KEYS:
            keys.add_row(key, description)
        about = Text.assemble(("\nVaultKey ", "bold"), (__version__, ""), ("\nVault  ", "dim"),
                              (short_path(self.app.pm.storage.filename, 60), ""),
                              ("\nAuto-lock after ", "dim"),
                              (f"{self.app.lock_after} idle minutes" if self.app.lock_after else "never", ""))
        with Vertical(classes="dialog"):
            yield Static("Keyboard shortcuts", classes="dialog-title")
            yield Static(Group(keys, about))
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close", variant="primary")

    @on(Button.Pressed, "#close")
    def close_button(self) -> None:
        self.dismiss(None)


# --- App --------------------------------------------------------------------------

class VaultKeyApp(App):
    TITLE = "VaultKey"
    CSS = """
    Screen { background: $background; }
    .hidden { display: none; }

    /* Unlock and create */
    UnlockScreen, CreateVaultScreen { align: center middle; }
    #card { width: 64; height: auto; padding: 1 3; border: round $accent 60%; background: $surface; }
    #card Input, #card Button { margin-top: 1; width: 100%; }
    #logo { color: $accent; text-align: center; width: 100%; text-style: bold; }
    .subtitle { color: $text-muted; text-align: center; width: 100%; margin-top: 1; }
    .hint { color: $text-muted; margin-top: 1; width: 100%; }
    #card .hint { text-align: center; }
    #message { margin-top: 1; text-align: center; width: 100%; }

    /* Main screen */
    #topbar { height: 1; padding: 0 2; margin-top: 1; }
    #brand { width: auto; color: $accent; }
    #stats { width: 1fr; text-align: right; }
    #search { margin: 1 2 0 2; }
    #main { height: 1fr; margin: 1 2 1 2; }
    #entries { width: 45%; height: 1fr; border: round $primary 30%; background: $surface; }
    #entries:focus { border: round $accent; }
    #detail { width: 1fr; height: 1fr; margin-left: 1; border: round $primary 30%; padding: 1 2; background: $surface; }
    #detail VerticalScroll { height: 1fr; }
    #actions { height: auto; }
    #actions Button { margin-right: 1; min-width: 12; }

    /* Dialogs */
    Dialog { align: center middle; background: $background 70%; }
    .dialog { width: 76; height: auto; max-height: 95%; padding: 1 2; border: round $accent 70%; background: $surface; }
    .dialog.narrow { width: 56; }
    .dialog.wide { width: 90; }
    .dialog-title { text-style: bold; color: $accent; margin-bottom: 1; }
    .field-label { color: $text-muted; margin-top: 1; }
    .muted { color: $text-muted; }
    .row { height: auto; }
    .row Input { width: 1fr; }
    .row Button { margin-left: 1; }
    .options { margin-top: 1; }
    .options Input { width: 9; }
    .inline-label { padding: 1 1 0 0; }
    #generated { padding: 1 2; margin-top: 1; border: round $success 50%; text-align: center; }
    #strength { margin-top: 1; height: auto; }
    #preview, #warning { margin-top: 1; height: auto; }
    #error { margin-top: 1; height: auto; }
    #history { height: auto; max-height: 20; }
    .buttons { height: auto; margin-top: 1; align-horizontal: right; }
    .buttons Button { margin-left: 1; }
    """

    def __init__(self, pm: PasswordManager, lock_after: int = DEFAULT_LOCK_MINUTES):
        super().__init__()
        self.pm = pm
        self.lock_after = lock_after
        self.last_activity = time.monotonic()

    def on_mount(self) -> None:
        self.theme = "tokyo-night"
        self.set_interval(5, self.check_inactivity)
        if not self.pm.storage.exists():
            self.push_screen(CreateVaultScreen())
            return
        crypto = resume_session(self.pm.storage.filename)
        if crypto is not None and self.pm.unlock_with_crypto(crypto):
            self.push_screen(VaultScreen())
            self.notify("Unlocked with your 'vk unlock' session")
        else:
            self.push_screen(UnlockScreen())

    async def on_event(self, event: events.Event) -> None:
        if isinstance(event, (events.Key, events.MouseDown, events.MouseScrollDown, events.MouseScrollUp)):
            self.last_activity = time.monotonic()
        await super().on_event(event)

    def check_inactivity(self) -> None:
        if (self.lock_after and self.pm.is_unlocked()
                and time.monotonic() - self.last_activity > self.lock_after * 60):
            self.lock_vault(f"Locked after {self.lock_after} idle minutes")

    def show_vault(self) -> None:
        self.switch_screen(VaultScreen())

    def lock_vault(self, message: str = "") -> None:
        self.pm.lock()
        while len(self.screen_stack) > 2:
            self.pop_screen()
        self.switch_screen(UnlockScreen(message))


def run_app(pm: PasswordManager, lock_after: int = DEFAULT_LOCK_MINUTES) -> None:
    """Entry point for `vk` / `vk interactive`"""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        ui.fail("The VaultKey app needs a terminal. Use the 'vk' commands in scripts.")
    try:
        VaultKeyApp(pm, lock_after).run()
    finally:
        pm.lock()
