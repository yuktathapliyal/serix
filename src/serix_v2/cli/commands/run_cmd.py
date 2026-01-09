"""
Serix v2 - Run Command (Stub/Alias)

Run Python scripts with capture/playback/fuzz modes.

Note: In v0.3.0, this command exists for backward compatibility.
Use 'serix dev' for script execution with enhanced features.
"""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from serix_v2.cli.theme import COLOR_WARNING

console = Console()


def run(
    script: Annotated[
        Path,
        typer.Argument(help="Python script to run"),
    ],
    fuzz: Annotated[
        bool,
        typer.Option("--fuzz", help="Enable fuzzing mode"),
    ] = False,
    fuzz_latency: Annotated[
        bool,
        typer.Option("--fuzz-latency", help="Inject latency"),
    ] = False,
    fuzz_errors: Annotated[
        bool,
        typer.Option("--fuzz-errors", help="Inject HTTP errors"),
    ] = False,
    fuzz_json: Annotated[
        bool,
        typer.Option("--fuzz-json", help="Inject JSON corruption"),
    ] = False,
) -> None:
    """Run a Python script with optional fuzzing (v0.2 compatibility mode)."""
    console.print()
    console.print(
        f"  [{COLOR_WARNING}]⚠[/{COLOR_WARNING}] The 'run' command is deprecated in v0.3.0"
    )
    console.print()
    console.print("  Use [dim]serix dev[/dim] instead for script execution:")
    console.print(f"    serix dev {script}")
    console.print()
    console.print("  Or use [dim]serix test[/dim] for security testing:")
    console.print(f'    serix test {script}:function_name --goal "..."')
    console.print()
    raise typer.Exit(0)
