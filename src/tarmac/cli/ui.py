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
    """Print a styled section header."""
    text = f"[bold cyan]{title}[/bold cyan]"
    if subtitle:
        text += f"\n[dim]{subtitle}[/dim]"
    console.print(Panel(text, box=box.ROUNDED, border_style="cyan", padding=(0, 2), expand=False))


def print_success(message: str) -> None:
    """Print a success message with a checkmark."""
    console.print(f"[bold green]✓[/bold green] {message}")


def print_info(message: str) -> None:
    """Print an informational message."""
    console.print(f"[cyan]ℹ[/cyan] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")


def print_step(phase: str, step_name: str) -> None:
    """Print a pipeline step banner."""
    console.print(
        f"\n[bold cyan]─── Phase {phase}[/bold cyan] [dim]|[/dim] [bold white]{step_name}[/bold white] [dim]───[/dim]"
    )
