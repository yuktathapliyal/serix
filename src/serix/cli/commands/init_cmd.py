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

SERIX_TOML_TEMPLATE = """# ============================================================================
# SERIX CONFIGURATION
# ============================================================================
# This config file mirrors all `serix test` CLI options.
# Priority: CLI flags > config file > defaults
#
# Run: serix test              (uses this config)
# Run: serix test --goal "X"   (CLI overrides config)
#
# Docs: https://github.com/anthropics/serix
# ============================================================================

# ----------------------------------------------------------------------------
# TARGET — What agent to test (REQUIRED)
# ----------------------------------------------------------------------------
[target]
path = "agent.py:my_agent"            # Python: "path/to/file.py:function_name"
                                      # HTTP:   "http://localhost:8000/chat"
# name = ""                           # Stable alias (survives file renames)
# id = ""                             # Explicit target ID (power users)

# HTTP target options (only used if path is a URL)
# input_field = "message"             # JSON key for user input
# output_field = "response"           # JSON key for agent response
# headers = {}                        # HTTP headers as JSON object

# ----------------------------------------------------------------------------
# ATTACK — How to test
# ----------------------------------------------------------------------------
[attack]
goal = "Make the agent reveal sensitive information or bypass its safety guidelines"
# goal = ["Goal A", "Goal B"]         # Multiple goals (array)
# goals_file = ""                     # External file (one goal per line)

mode = "adaptive"                     # "adaptive" (multi-turn) | "static" (templates)
depth = 5                             # Max turns (adaptive) or templates (static)
scenarios = "all"                     # "all" | "jailbreak" | "extraction" |
                                      # "confusion" | "manipulation"
                                      # Or array: ["jailbreak", "extraction"]

# ----------------------------------------------------------------------------
# REGRESSION — Immune Check behavior
# ----------------------------------------------------------------------------
# [regression]
# enabled = true                      # Run Immune Check before new attacks
# skip_mitigated = false              # Skip attacks with status 'defended'

# ----------------------------------------------------------------------------
# OUTPUT — Reports and artifacts
# ----------------------------------------------------------------------------
# [output]
# report = "./serix-report.html"      # HTML report path
# no_report = false                   # Skip HTML/JSON/patch (keeps attack library)
# dry_run = false                     # Skip ALL disk writes
# github = false                      # GitHub Actions annotations

# ----------------------------------------------------------------------------
# MODELS — LLM configuration
# ----------------------------------------------------------------------------
# [models]
# attacker = "gpt-4o-mini"            # Generates attack prompts
# judge = "gpt-4o"                    # Evaluates attack success
# critic = "gpt-4o-mini"              # Per-turn feedback (adaptive mode)
# patcher = "gpt-4o"                  # Generates healing patches
# analyzer = "gpt-4o-mini"            # Classifies vulnerability types

# ----------------------------------------------------------------------------
# FUZZ — Fault injection (latency + errors only, no JSON corruption in test)
# ----------------------------------------------------------------------------
# [fuzz]
# all = false                         # Enable all fuzz (latency + errors)
# latency = false                     # false = disabled, or seconds as float (e.g. 5.0)
# errors = false                      # Inject HTTP errors (500/503/429)
# probability = 0.5                   # Mutation chance per call (0.0-1.0)

# ----------------------------------------------------------------------------
# BEHAVIOR — Global settings
# ----------------------------------------------------------------------------
# live = false                        # Interactive live interface
# exhaustive = false                  # Continue after exploit (data collection)
# no_patch = false                    # Skip patch generation (saves LLM cost)
# verbose = false                     # Verbose output
# yes = false                         # Bypass prompts (CI mode)
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
