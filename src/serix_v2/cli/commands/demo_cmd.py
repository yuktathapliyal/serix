"""
Serix v2 - Demo Command (Stub)

Run the bundled vulnerable agent demonstration.

DEFERRED: Full implementation planned for Phase 11C.
This stub exists so gate.sh smoke tests pass.
"""

import typer
from rich.console import Console

from serix_v2.cli.theme import COLOR_WARNING

console = Console()


def demo(
    no_live: bool = typer.Option(
        False,
        "--no-live",
        help="Run without interactive interface",
    ),
) -> None:
    """Run bundled vulnerable agent demo (coming in Phase 11C)."""
    console.print()
    console.print(
        f"  [{COLOR_WARNING}]⚠[/{COLOR_WARNING}] Demo command not yet implemented"
    )
    console.print()
    console.print("  The demo command will be available in Phase 11C.")
    console.print("  For now, use [dim]serix test[/dim] with your own agent:")
    console.print()
    console.print('    serix test agent.py:my_agent --goal "reveal secrets"')
    console.print()
    raise typer.Exit(0)
