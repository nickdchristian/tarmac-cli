"""Showing a dry-run plan."""

from rich.text import Text

from ..services.plan import DeploymentPlan
from .ui import console, create_table, print_header, print_info

_ACTION_STYLES = {
    "CREATE": "green",
    "IMPORT": "green",
    "UPDATE": "yellow",
    "APPLY": "yellow",
    "MOVE": "yellow",
    "REPLACE": "red",
    "SUSPEND": "red",
    "BLOCKED": "red",
    "UNKNOWN": "red",
}


def render_plan(plan: DeploymentPlan) -> None:
    print_header("Deployment plan (dry run)", f"Region {plan.region}. Nothing is changed.")
    for phase in plan.phases:
        table = create_table(title=f"Phase {phase.phase}: {phase.title}")
        table.add_column("Kind", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Account", style="magenta")
        table.add_column("Action", justify="center")
        table.add_column("Detail", style="dim")
        for item in phase.items:
            style = _ACTION_STYLES.get(item.action, "dim")
            table.add_row(
                item.kind,
                Text(item.name),
                Text(item.account),
                Text(item.action, style=style),
                Text(item.detail),
            )
        console.print(table)
        for note in phase.notes:
            print_info(note)
    counts = plan.counts()
    if counts:
        print_info("Summary: " + ", ".join(f"{count} {action}" for action, count in sorted(counts.items())))
    print_info("Run without --dry-run to apply.")
