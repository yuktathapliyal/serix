"""
Serix v2 - CLI Application Entry Point

Main Typer application that wires together all commands.

Law 2 Compliance: This is in cli/, so typer/rich allowed.
This is the ONLY entry point for the CLI.

Usage:
    serix init
    serix status
    serix test agent.py:fn --goal "..."
"""

from typing import Optional

import typer
from click import Context
from click.formatting import HelpFormatter
from rich.console import Console
from rich.table import Table
from rich.text import Text
from typer.core import TyperGroup

from serix_v2.cli.commands import demo, init, run, status, test
from serix_v2.cli.subcommand_help import InitHelpCommand, TestHelpCommand
from serix_v2.cli.theme import (
    COLOR_COMMAND,
    COLOR_DIM,
    COLOR_GOAL,
    COLOR_SUBTITLE,
    COLOR_URL,
    CONTENT_WIDTH,
    DOCS_URL,
    FIRST_COL_WIDTH,
    GLOBAL_MARGIN,
    ITEM_INDENT,
    SUBTITLE_TEXT,
    TAGLINE_LINES,
    create_gradient_brand,
)

# Console instances
console = Console()  # For version callback
_help_console = Console(
    highlight=False, soft_wrap=True
)  # For help screen (prevents auto-coloring)

# Command order and help text for the main help screen
COMMAND_ORDER = ["test", "status", "init", "demo"]
COMMAND_HELP = {
    "test": "Audit an agent and generate a security report with fixes",
    "status": "View your agent audit history and security scorecards",
    "init": "Configure settings for your workspace",
    "demo": "Audit a sample agent to see serix in action",
}

# Options for the main help screen
OPTIONS = [
    ("--version", "Show version and exit"),
    ("--help", "Show help and exit"),
]

# Get started examples: (command, description, has_goal_highlight)
# has_goal_highlight indicates the command contains pre-styled goal text
GET_STARTED_EXAMPLES = [
    ("serix demo", "Watch serix find and fix vulnerabilities in a sample agent", False),
    (
        "serix test agent.py:my_fn --goal",
        "Run a security audit on your own agent",
        True,
    ),
    (
        "serix \\[command] --help",
        "View detailed options and examples for any command",
        False,
    ),
]
GOAL_EXAMPLE_TEXT = '"extract customer PII"'


# =============================================================================
# Section Rendering Functions
# =============================================================================


def _render_header() -> None:
    """Render the header with gradient brand logo and right-aligned subtitle."""
    # Add blank line for spacing after shell command
    _help_console.print()

    # Calculate spacing to align subtitle with content width
    # Content width = 86, brand starts at column 2, brand is 9 chars, subtitle is 22 chars
    # Spacing = CONTENT_WIDTH - GLOBAL_MARGIN - len(brand) - len(subtitle)
    brand_len = len("S E R I X")
    subtitle_len = len(SUBTITLE_TEXT)
    spacing = CONTENT_WIDTH - GLOBAL_MARGIN - brand_len - subtitle_len

    # Build the header line
    indent = " " * GLOBAL_MARGIN
    header_text = Text(indent)
    header_text.append_text(create_gradient_brand())
    header_text.append(" " * spacing)
    header_text.append(SUBTITLE_TEXT, style=COLOR_SUBTITLE)

    _help_console.print(header_text)
    _help_console.print()


def _render_tagline() -> None:
    """Render the tagline with 2-space indent."""
    indent = " " * GLOBAL_MARGIN
    for line in TAGLINE_LINES:
        _help_console.print(f"{indent}[{COLOR_DIM}]{line}[/{COLOR_DIM}]")
    _help_console.print()


def _render_commands_section() -> None:
    """Render the Commands section with proper grid alignment."""
    indent = " " * GLOBAL_MARGIN
    # Chevron prefix: 2 spaces + › + space = 4 chars (same as ITEM_INDENT)
    chevron_prefix = f"  [{COLOR_DIM}]›[/{COLOR_DIM}] "

    _help_console.print(f"{indent}[{COLOR_DIM}]Commands:[/{COLOR_DIM}]")

    table = Table.grid(padding=(0, 2))
    table.add_column(width=FIRST_COL_WIDTH)
    table.add_column()

    for name in COMMAND_ORDER:
        help_text = COMMAND_HELP.get(name, "")
        command_cell = f"{chevron_prefix}[{COLOR_COMMAND}]{name}[/{COLOR_COMMAND}]"
        desc_cell = f"[{COLOR_DIM}]{help_text}[/{COLOR_DIM}]"
        table.add_row(command_cell, desc_cell)

    _help_console.print(table)
    _help_console.print()


def _render_options_section() -> None:
    """Render the Options section with proper grid alignment."""
    indent = " " * GLOBAL_MARGIN
    item_indent = " " * ITEM_INDENT

    _help_console.print(f"{indent}[{COLOR_DIM}]Options:[/{COLOR_DIM}]")

    table = Table.grid(padding=(0, 2))
    table.add_column(width=FIRST_COL_WIDTH)
    table.add_column()

    for option, description in OPTIONS:
        option_cell = f"{item_indent}[{COLOR_COMMAND}]{option}[/{COLOR_COMMAND}]"
        desc_cell = f"[{COLOR_DIM}]{description}[/{COLOR_DIM}]"
        table.add_row(option_cell, desc_cell)

    _help_console.print(table)
    _help_console.print()


def _render_get_started_section() -> None:
    """Render the Get started section with comment-style descriptions."""
    indent = " " * GLOBAL_MARGIN
    item_indent = " " * ITEM_INDENT

    _help_console.print(f"{indent}[{COLOR_DIM}]Get started:[/{COLOR_DIM}]")

    for command, description, has_goal in GET_STARTED_EXAMPLES:
        # Build command with optional goal highlight
        if has_goal:
            command_styled = (
                f"{item_indent}[{COLOR_COMMAND}]{command}[/{COLOR_COMMAND}] "
                f"[{COLOR_GOAL}]{GOAL_EXAMPLE_TEXT}[/{COLOR_GOAL}]"
            )
        else:
            command_styled = (
                f"{item_indent}[{COLOR_COMMAND}]{command}[/{COLOR_COMMAND}]"
            )

        # Format: command  # description (comment-style)
        line = f"{command_styled}  [{COLOR_DIM}]# {description}[/{COLOR_DIM}]"
        _help_console.print(line)

    _help_console.print()


def _render_docs_section() -> None:
    """Render the Docs section on a single line."""
    indent = " " * GLOBAL_MARGIN

    # Docs label and URL on same line, single space
    _help_console.print(
        f"{indent}[{COLOR_DIM}]Docs:[/{COLOR_DIM}] [{COLOR_URL}]{DOCS_URL}[/{COLOR_URL}]"
    )


# =============================================================================
# Custom Help Group
# =============================================================================


class PlainHelpGroup(TyperGroup):
    """Custom help formatter for Cyberpunk Professional UI."""

    def format_help(self, ctx: Context, formatter: HelpFormatter) -> None:
        """Render custom help with gradient brand and strict grid system."""
        _render_header()
        _render_tagline()
        _render_commands_section()
        _render_get_started_section()
        _render_options_section()
        _render_docs_section()

    def format_usage(self, ctx: Context, formatter: HelpFormatter) -> None:
        """Override to hide usage line."""
        pass  # Empty - no usage line


# =============================================================================
# Typer Application
# =============================================================================


app = typer.Typer(
    name="serix",
    cls=PlainHelpGroup,
    add_completion=False,
    no_args_is_help=True,
)


# Version callback
def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print("serix v0.3.0")
        raise typer.Exit()


# Register commands with descriptions matching COMMAND_HELP
app.command("demo", help=COMMAND_HELP["demo"])(demo)
app.command("init", help=COMMAND_HELP["init"], cls=InitHelpCommand)(init)
app.command("run", hidden=True)(run)  # Hidden - v0.2 backward compat only
app.command("status", help=COMMAND_HELP["status"])(status)
app.command("test", help=COMMAND_HELP["test"], cls=TestHelpCommand)(test)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """Serix - Agent Security Testing."""
    pass


if __name__ == "__main__":
    app()
