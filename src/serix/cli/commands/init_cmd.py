"""Init command implementation.

Provides the `serix init` command for generating configuration files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from ...core.constants import CONFIG_FILENAME
from ...ui import render

console = Console()

SERIX_TOML_TEMPLATE = """# Serix Configuration
# Documentation: https://github.com/serix-ai/serix

[attack]
# Default attack depth (turns per persona)
depth = 5

# Attack mode: "adaptive" or "static"
mode = "adaptive"

# Default scenarios (comma-separated or "all")
# Available: jailbreak, extraction, confusion, manipulation
scenarios = "all"

[models]
# Models used for different purposes
attacker = "gpt-4o-mini"    # Generates attack prompts
judge = "gpt-4o"            # Evaluates attack success
critic = "gpt-4o"           # Reviews prompts (adaptive mode)
patcher = "gpt-4o"          # Generates healing patches
analyzer = "gpt-4o"         # Analyzes vulnerabilities

[output]
# Default report filename
report = "serix-report.html"

# Skip report generation by default
no_report = false

[dev]
# Recordings directory for capture/playback
recording_dir = "captures"

# Default fuzzing settings
fuzz_latency = false
fuzz_errors = false
fuzz_json = false
"""


def init_command(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing configuration",
        ),
    ] = False,
    path: Annotated[
        Path | None,
        typer.Option(
            "--path",
            "-p",
            help="Custom config path (default: serix.toml)",
        ),
    ] = None,
) -> None:
    """Initialize serix.toml configuration file.

    Creates a template configuration file with documented defaults.

    Examples:

        serix init

        serix init --force

        serix init --path .serix.toml
    """
    config_path = path or Path(CONFIG_FILENAME)

    if config_path.exists() and not force:
        render.warning(console, f"{config_path} already exists.")
        console.print("Use [bold]--force[/bold] to overwrite.")
        raise typer.Exit(1)

    config_path.write_text(SERIX_TOML_TEMPLATE)
    render.success(console, f"Created {config_path}")
    console.print("\nEdit this file to customize Serix behavior.")
