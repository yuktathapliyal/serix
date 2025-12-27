"""Serix CLI - Core app and main callback.

This module contains the Typer app instance and main callback.
All commands are registered in cli/__init__.py.

Legacy commands have been removed in v0.3.0. Use the new commands:
- serix test    (replaces serix test, serix attack)
- serix demo    (replaces serix demo)
- serix dev     (replaces serix run, serix record, serix replay)
- serix status  (new - target health dashboard)
- serix init    (new - generate serix.toml)
"""

from __future__ import annotations

from typing import Annotated

import typer

from serix.ui import get_console, render
from serix.ui.theme import is_interactive as ui_is_interactive

app = typer.Typer(
    name="serix",
    help="AI agent testing framework with recording, replay, and fuzzing.",
    no_args_is_help=False,  # We handle this in the callback
    add_completion=False,
)
console = get_console()


def _version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        from serix import __version__

        typer.echo(f"serix {__version__}")
        raise typer.Exit()


def _help_callback(ctx: typer.Context, value: bool) -> None:
    """Custom help callback with Serix visual identity."""
    if not value:
        return

    from serix import __version__

    console.print()  # Visual separation from command prompt

    # Show banner (only in interactive mode)
    if ui_is_interactive():
        render.banner(console, __version__)
    else:
        console.print(f"[serix.brand]SERIX[/] v{__version__}")
    console.print()

    # Show description
    console.print(
        "AI agent security testing framework with red teaming, recording, and replay."
    )
    console.print()

    # Commands list with descriptions (v0.3.0 architecture)
    commands = [
        ("test", "Execute adversarial security campaigns against an agent"),
        ("demo", "Run the bundled vulnerable agent for quick verification"),
        ("dev", "Run a script with capture, playback, or fault injection"),
        ("status", "Show security status for all tested targets"),
        ("init", "Scaffold a new serix.toml configuration file"),
    ]
    render.command_list(console, commands)
    console.print()

    # Options
    options = [
        ("--version, -V", "", "Show version and exit"),
        ("--help", "", "Show this message and exit"),
    ]
    render.option_list(console, options)
    console.print()

    # Usage tip
    console.print(
        "[serix.muted]Run 'serix <command> --help' for command-specific options.[/]"
    )
    console.print()  # Trailing newline for visual separation

    raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
    help_flag: Annotated[
        bool,
        typer.Option(
            "--help",
            "-h",
            callback=_help_callback,
            is_eager=True,
            help="Show help and exit.",
        ),
    ] = False,
) -> None:
    """Serix - AI agent testing framework."""
    # If no subcommand was invoked, show help
    if ctx.invoked_subcommand is None:
        _help_callback(ctx, True)
