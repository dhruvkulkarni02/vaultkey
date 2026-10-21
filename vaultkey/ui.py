"""
ui.py - Shared terminal output for the VaultKey CLI and interactive mode

Data (tables, passwords, JSON) goes to stdout; status messages go to stderr, so
`vk ... --json` output can be piped. Colour follows the terminal and NO_COLOR.
"""
import json
import sys
from datetime import datetime
from typing import Any, Optional, Tuple

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

MASK = "••••••••"
OLD_AFTER_DAYS = 90


def user(text: Any) -> str:
    """Escape user-provided text so rich doesn't treat [brackets] as markup"""
    return escape(str(text))


def success(message: str) -> None:
    err_console.print(f"[green]✔[/] {message}")


def info(message: str) -> None:
    err_console.print(f"[cyan]›[/] {message}")


def warning(message: str) -> None:
    err_console.print(f"[yellow]![/] {message}")


def error(message: str) -> None:
    err_console.print(f"[bold red]✘[/] {message}")


def fail(message: str, code: int = 1) -> None:
    """Print an error and exit with a non-zero status"""
    error(message)
    sys.exit(code)


def print_json(data: Any) -> None:
    """Print machine-readable output (plain JSON, no styling or wrapping)"""
    sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def new_table(*columns: str, title: Optional[str] = None) -> Table:
    table = Table(*columns, title=title, box=box.SIMPLE_HEAD, header_style="bold", title_justify="left")
    return table


def strength_label(score: int) -> Tuple[str, str]:
    """(label, colour) for a 0-100 strength score"""
    if score >= 80:
        return "Strong", "green"
    if score >= 60:
        return "Good", "green"
    if score >= 40:
        return "Weak", "yellow"
    return "Very weak", "red"


def strength_text(score: int) -> str:
    """Strength as a short coloured meter, e.g. '●●●○ Good 72'"""
    label, colour = strength_label(score)
    filled = 4 if score >= 80 else 3 if score >= 60 else 2 if score >= 40 else 1
    return f"[{colour}]{'●' * filled}[/][dim]{'○' * (4 - filled)}[/] {label} [dim]{score}[/]"


def age_in_days(timestamp: Optional[str]) -> Optional[int]:
    """Days since an ISO timestamp, or None if missing/invalid"""
    try:
        return max(0, (datetime.now() - datetime.fromisoformat(timestamp or "")).days)
    except ValueError:
        return None


def format_age(days: Optional[int]) -> str:
    if days is None:
        return "unknown"
    if days == 0:
        return "today"
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days}d ago"
    if days < 365:
        return f"{days // 30}mo ago"
    return f"{days // 365}y ago"


def entry_json(site: str, entry: dict, include_password: bool) -> dict:
    """Public JSON shape of a vault entry"""
    data = {
        "site": site,
        "username": entry.get("username", ""),
        "notes": entry.get("notes", ""),
        "created": entry.get("created", ""),
        "modified": entry.get("modified", ""),
    }
    if include_password:
        data["password"] = entry.get("password", "")
    return data
