"""
Serix v2 - Init Command

Creates serix.toml configuration file.

Law 2 Compliance: This is in cli/, so typer/rich allowed.
Business logic is in InitService (no CLI deps).
"""

from pathlib import Path
from typing import Annotated

import typer

from serix_v2.cli.renderers.console import (
    render_init_exists,
    render_init_replaced,
    render_init_success,
)
from serix_v2.services import InitService


def init(
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Overwrite existing serix.toml"),
    ] = False,
) -> None:
    """Create a serix.toml configuration file in the current directory."""
    config_path = Path("serix.toml")
    backup_path = Path("serix.toml.bak")

    # Check if config exists
    if config_path.exists() and not force:
        render_init_exists(str(config_path))
        raise typer.Exit(1)

    # Create backup if overwriting
    if config_path.exists() and force:
        config_path.rename(backup_path)

    # Generate template via service
    service = InitService()
    result = service.generate()

    # Write config file
    config_path.write_text(result.template)

    # Render success message
    if force and backup_path.exists():
        render_init_replaced(str(config_path), str(backup_path))
    else:
        render_init_success(str(config_path), result.version)
