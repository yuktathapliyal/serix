"""CLI package - commands and output formatting.

This module maintains backwards compatibility by re-exporting `app`
from the legacy monolith. New commands are added here as they're built.
"""

from .commands.demo_cmd import demo_command

# Register new v0.3.0 commands directly on the app
from .commands.dev_cmd import dev_command
from .commands.init_cmd import init_command
from .commands.status_cmd import status_command
from .commands.test_cmd import test_command
from .legacy import app

# Sprint 5: New architecture commands
# -----------------------------------
# Primary test command (renamed from test2)
app.command(name="test")(test_command)

# Demo command - showcases Serix capabilities
app.command(name="demo")(demo_command)

# Add dev command - replaces legacy run/record/replay
app.command(name="dev")(dev_command)

# Add status command - target health dashboard
app.command(name="status")(status_command)

# Add init command - generate serix.toml
app.command(name="init")(init_command)

# Note: Legacy commands (run, record, replay, demo, test) are hidden in legacy.py.
# New architecture commands are now primary.

__all__ = ["app"]
