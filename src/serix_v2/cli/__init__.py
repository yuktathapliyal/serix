"""
Serix v2 - CLI Module

Law 2 Compliant: CLI layer with typer/rich allowed.
This module is the ONLY place where typer, rich, and click are permitted.

Structure:
    cli/
    ├── app.py          # Typer app + entry point
    ├── commands/       # Command implementations
    │   ├── init_cmd.py
    │   ├── status_cmd.py
    │   └── test_cmd.py
    └── renderers/      # Display formatting
        ├── console.py  # Rich console output
        └── github.py   # GitHub Actions output
"""

from serix_v2.cli.app import app

__all__ = ["app"]
