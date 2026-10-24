"""Rich console helpers shared by the CLI commands."""

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def create_table(title: str | None = None, **kwargs: Any) -> Table:
    """Create a consistently styled Rich table for Tarmac CLI output."""
    defaults: dict[str, Any] = {
        "box": box.ROUNDED,
        "header_style": "bold cyan",
        "title_style": "bold white",
        "border_style": "dim cyan",
        "show_header": True,
    }
    defaults.update(kwargs)
    if title:
        return Table(title=title, **defaults)
    return Table(**defaults)


def print_header(title: str, subtitle: str = "") -> None:
    text = f"[bold cyan]{title}[/bold cyan]"
    if subtitle:
        text += f"\n[dim]{subtitle}[/dim]"
    console.print(Panel(text, box=box.ROUNDED, border_style="cyan", padding=(0, 2), expand=False))


def print_success(message: str) -> None:
    console.print(f"[green]{message}[/green]")


def print_info(message: str) -> None:
    """Print an informational message."""
    console.print(message)


def print_warning(message: str) -> None:
    console.print(f"[bold yellow]Warning:[/bold yellow] {message}")


def print_action_panel(
    rows: list[tuple[str, str, str]],
    *,
    has_failures: bool,
    titles: tuple[str, str],
    item_header: str,
    item_width: int,
    action_header: str,
) -> None:
    """Render (badge, item, action) rows in a red panel when anything failed, else a yellow one.

    ``titles`` is (title when failing, title otherwise).
    """
    color = "red" if has_failures else "yellow"
    title = titles[0] if has_failures else titles[1]
    table = Table(box=box.SIMPLE, header_style=f"bold {color}", expand=True, show_header=True)
    table.add_column("Status", justify="center", width=8, min_width=8, no_wrap=True)
    table.add_column(item_header, style="bold white", width=item_width, no_wrap=True)
    table.add_column(action_header, style="white")
    for row in rows:
        table.add_row(*row)
    console.print(
        Panel(
            table,
            title=f"[bold {color}]{title}[/bold {color}]",
            border_style=color,
            padding=(0, 1),
            expand=True,
        )
    )


def print_step(phase: str, step_name: str) -> None:
    console.print(
        f"\n[bold cyan]─── Phase {phase}[/bold cyan] [dim]|[/dim] [bold white]{step_name}[/bold white] [dim]───[/dim]"
    )
