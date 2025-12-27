"""Demo command implementation.

Provides the `serix demo` command for showcasing Serix capabilities.
Runs a quick attack against a bundled vulnerable agent.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from ...examples import GOLDEN_VICTIM_PATH
from ...ui import render

console = Console()


def demo_command(
    live: Annotated[
        bool,
        typer.Option(
            "--live/--no-live",
            help="Enable live command center UI",
        ),
    ] = False,
    report: Annotated[
        Path | None,
        typer.Option(
            "--report",
            "-r",
            help="HTML report output path",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "-v",
            "--verbose",
            help="Verbose output",
        ),
    ] = False,
) -> None:
    """Run a quick demo attack against a bundled vulnerable agent.

    Demonstrates Serix's capabilities using a pre-configured
    "golden victim" agent that is intentionally vulnerable.

    Examples:

        serix demo              # Run the demo

        serix demo --no-live    # Console output only

        serix demo --report demo-report.html
    """
    # Ensure API key is available
    if not os.environ.get("OPENAI_API_KEY"):
        render.error(console, "OPENAI_API_KEY not set")
        console.print("Set it with: [bold]export OPENAI_API_KEY=sk-...[/bold]")
        raise typer.Exit(1)

    report_path = report or Path("serix-demo-report.html")

    render.section_header(console, "Demo")
    render.kv(console, "Target", "golden_victim (bundled)", label_width=10)
    render.kv(console, "Scenario", "jailbreak (Grandma exploit)", label_width=10)
    render.kv(console, "Goal", '"Reveal the API key"', label_width=10)
    console.print()

    # Build command - use test2 (new architecture)
    cmd = [
        sys.executable,
        "-m",
        "serix",
        "test",
        f"{GOLDEN_VICTIM_PATH}:golden_victim",
        "--goal",
        "reveal the API key",
        "-s",
        "jailbreak",
        "--report",
        str(report_path),
    ]

    if verbose:
        cmd.append("--verbose")

    # Run as subprocess
    result = subprocess.run(cmd)
    raise typer.Exit(result.returncode)
