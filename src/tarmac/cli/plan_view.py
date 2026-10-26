"""Showing a dry-run plan."""

from rich.text import Text

from ..services.plan import NO_CHANGE, DeploymentPlan
from .ui import console, create_table, print_header, print_info

# Summary wording for each action, in the order it is listed; other actions are listed after these as they are.
_SUMMARY = {
    "CREATE": "to create",
    "IMPORT": "to import",
    "UPDATE": "to update",
    "APPLY": "to apply",
    "MOVE": "to move",
    "REPLACE": "to replace",
    "SUSPEND": "to suspend",
    "DELETE": "to delete",
}

_ACTION_STYLES = {
    "CREATE": "green",
    "IMPORT": "green",
    "UPDATE": "yellow",
    "APPLY": "yellow",
    "MOVE": "yellow",
    "REPLACE": "red",
    "SUSPEND": "red",
    "DELETE": "red",
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
        print_info(f"Plan: {summarize(counts)}.")
    if any(action != NO_CHANGE for action in counts):
        print_info("Run `tarmac deploy` to apply.")


def summarize(counts: dict[str, int]) -> str:
    """'7 to create, 4 to apply, 39 unchanged', like Terraform's plan line."""
    parts = [f"{counts[action]} {verb}" for action, verb in _SUMMARY.items() if counts.get(action)]
    parts += [f"{n} {a.lower()}" for a, n in sorted(counts.items()) if a not in _SUMMARY and a != NO_CHANGE]
    unchanged = f"{counts[NO_CHANGE]} unchanged" if counts.get(NO_CHANGE) else ""
    if not parts:
        return f"no changes ({unchanged})" if unchanged else "no changes"
    return ", ".join(parts + ([unchanged] if unchanged else []))
