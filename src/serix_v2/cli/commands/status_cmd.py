"""
Serix v2 - Status Command

View attack library status across all tested targets.

Law 2 Compliance: This is in cli/, so typer/rich allowed.
Business logic is in StatusService (no CLI deps).

Guardrail 3: Uses correct method names:
- get_all_targets() NOT get_summary()
- get_by_name() NOT get_target_by_name()
"""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from serix_v2.cli.renderers.console import (
    render_single_target_status,
    render_status_table,
    render_target_not_found,
)
from serix_v2.services import StatusService, StatusSummary

console = Console()


def status(
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Filter by target alias"),
    ] = None,
    target_id: Annotated[
        str | None,
        typer.Option("--target-id", help="Filter by explicit target ID"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Machine-readable JSON output"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("-v", "--verbose", help="Show per-attack details"),
    ] = False,
) -> None:
    """View attack library status across all tested targets."""
    service = StatusService(base_dir=Path(".serix"))

    # Get status (filtered or all) - Guardrail 3: CORRECT method names
    if target_id:
        target_status = service.get_target_status(target_id)  # CORRECT
        if target_status is None:
            render_target_not_found(target_id=target_id)
            raise typer.Exit(2)
        # Wrap single target in summary for consistent output
        summary = StatusSummary(
            total_targets=1,
            total_attacks=target_status.total_attacks,
            total_exploited=target_status.exploited,
            total_defended=target_status.defended,
            targets=[target_status],
        )
    elif name:
        target_status = service.get_by_name(name)  # CORRECT (not get_target_by_name)
        if target_status is None:
            render_target_not_found(name=name)
            raise typer.Exit(2)
        summary = StatusSummary(
            total_targets=1,
            total_attacks=target_status.total_attacks,
            total_exploited=target_status.exploited,
            total_defended=target_status.defended,
            targets=[target_status],
        )
    else:
        summary = service.get_all_targets()  # CORRECT (not get_summary)

    # Output format - Guardrail 5: display logic in renderers
    if json_output:
        console.print(summary.model_dump_json(indent=2))
    elif target_id or name:
        # Single target view
        render_single_target_status(summary.targets[0], verbose=verbose)
    else:
        # Multi-target table view
        render_status_table(summary, verbose=verbose)
