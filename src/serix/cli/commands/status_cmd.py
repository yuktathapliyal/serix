"""Status command implementation.

Provides the `serix status` command for viewing target health dashboard.
Shows all tested targets and their security status.
"""

from __future__ import annotations

import json as json_module
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from ...services.storage import StorageService

console = Console()


def status_command(
    name: Annotated[
        str | None,
        typer.Option(
            "--name",
            "-n",
            help="Filter by target name/alias",
        ),
    ] = None,
    json: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output as JSON",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "-v",
            "--verbose",
            help="Show per-attack details (goals, strategies, statuses)",
        ),
    ] = False,
) -> None:
    """Show status dashboard for all tested targets.

    Displays:

    - Target name and identifier

    - Total attacks run

    - Number exploited (still vulnerable)

    - Number defended (now fixed)

    - Health score (defended / total)

    Examples:

        serix status                  # All targets

        serix status --name my-agent  # Single target

        serix status --json           # JSON output
    """
    storage = StorageService()

    if not storage.exists():
        if json:
            console.print("[]")
        else:
            console.print("[yellow]No .serix/ directory found.[/yellow]")
            console.print("Run [bold]serix test[/bold] to create one.")
        raise typer.Exit(0)

    # Get all targets
    target_ids = storage.list_targets()

    if not target_ids:
        if json:
            console.print("[]")
        else:
            console.print("[yellow]No targets found.[/yellow]")
        raise typer.Exit(0)

    # Build status data
    statuses: list[dict] = []
    aliases = storage.list_aliases()
    reverse_aliases = {v: k for k, v in aliases.items()}

    for target_id in target_ids:
        metadata = storage.load_metadata(target_id)
        attacks = storage.get_all_attacks(target_id)

        # Use alias if available, otherwise truncated ID
        target_name = reverse_aliases.get(target_id, target_id[:8])

        # Filter by name if specified
        if name:
            name_lower = name.lower()
            if (
                name_lower not in target_name.lower()
                and name_lower not in target_id.lower()
            ):
                continue

        exploited = sum(1 for a in attacks if a.status == "exploited")
        defended = sum(1 for a in attacks if a.status == "defended")
        total = len(attacks)
        health = (defended / total * 100) if total > 0 else 100.0

        # Get last tested time from most recent attack
        last_tested = None
        if attacks:
            last_tested = max(a.last_tested for a in attacks)

        statuses.append(
            {
                "name": target_name,
                "target_id": target_id,
                "locator": metadata.locator if metadata else "unknown",
                "total_attacks": total,
                "exploited": exploited,
                "defended": defended,
                "health": health,
                "last_tested": last_tested.isoformat() if last_tested else None,
                "attacks": [
                    {
                        "goal": a.goal,
                        "strategy": a.strategy_id,
                        "status": a.status,
                        "owasp_code": a.owasp_code,
                    }
                    for a in attacks
                ],
            }
        )

    if not statuses:
        if name:
            if json:
                console.print("[]")
            else:
                console.print(f"[yellow]No targets matching '{name}' found.[/yellow]")
        else:
            if json:
                console.print("[]")
            else:
                console.print("[yellow]No targets found.[/yellow]")
        raise typer.Exit(0)

    # Output
    if json:
        console.print(json_module.dumps(statuses, indent=2, default=str))
    else:
        _print_table(statuses, verbose=verbose)


def _print_table(statuses: list[dict], verbose: bool = False) -> None:
    """Print status table with colors."""
    table = Table(title="Serix Target Status")

    table.add_column("Name", style="bold")
    if verbose:
        table.add_column("Target ID", style="dim")
    table.add_column("Locator", style="dim")
    table.add_column("Attacks", justify="right")
    table.add_column("Exploited", justify="right")
    table.add_column("Defended", justify="right")
    table.add_column("Health", justify="right")

    for s in statuses:
        # Color health based on score
        health = s["health"]
        if health >= 100:
            health_str = f"[green]{health:.0f}%[/green]"
        elif health >= 50:
            health_str = f"[yellow]{health:.0f}%[/yellow]"
        else:
            health_str = f"[red]{health:.0f}%[/red]"

        # Color exploited
        exploited = s["exploited"]
        if exploited > 0:
            exploited_str = f"[red]{exploited}[/red]"
        else:
            exploited_str = f"[green]{exploited}[/green]"

        # Truncate locator if too long
        locator = s["locator"]
        if len(locator) > 40:
            locator = locator[:37] + "..."

        row = [s["name"]]
        if verbose:
            row.append(s["target_id"])
        row.extend(
            [
                locator,
                str(s["total_attacks"]),
                exploited_str,
                str(s["defended"]),
                health_str,
            ]
        )
        table.add_row(*row)

    console.print(table)

    # Show per-attack details when verbose
    if verbose:
        for s in statuses:
            attacks = s.get("attacks", [])
            if not attacks:
                continue

            console.print()
            console.print(f"[bold]{s['name']}[/bold] — Attack Details:")

            attack_table = Table(show_header=True, box=None, padding=(0, 2))
            attack_table.add_column("Goal", style="dim", max_width=50)
            attack_table.add_column("Strategy", style="cyan")
            attack_table.add_column("Status", justify="center")
            attack_table.add_column("OWASP", style="dim")

            for attack in attacks:
                # Truncate goal if too long
                goal = attack["goal"]
                if len(goal) > 50:
                    goal = goal[:47] + "..."

                # Color status
                status = attack["status"]
                if status == "exploited":
                    status_str = "[red]EXPLOITED[/red]"
                else:
                    status_str = "[green]DEFENDED[/green]"

                owasp = attack.get("owasp_code") or "-"

                attack_table.add_row(goal, attack["strategy"], status_str, owasp)

            console.print(attack_table)
