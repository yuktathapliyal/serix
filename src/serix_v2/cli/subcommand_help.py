"""
Serix v2 - Subcommand Help System

Styled help formatters for subcommands (init, status, demo, test).
Applies the CLI design system from SPEC-CLI-DESIGN-SYSTEM.md.

Law 2 Compliance: This is in cli/, so typer/rich allowed.
"""

from click import Context
from click.formatting import HelpFormatter
from rich.console import Console
from rich.table import Table
from rich.text import Text
from typer.core import TyperCommand

from serix_v2.cli.theme import (
    COLOR_COMMAND,
    COLOR_DIM,
    COLOR_SUBTITLE,
    COLOR_URL,
    DOCS_URL,
    FIRST_COL_WIDTH,
    GLOBAL_MARGIN,
    ITEM_INDENT,
    OVERFLOW_THRESHOLD,
    SUBTITLE_TEXT,
    create_gradient_brand,
)

# Console for help rendering (prevents auto-coloring)
_help_console = Console(highlight=False, soft_wrap=True)


# =============================================================================
# Section Rendering Functions
# =============================================================================


def _render_subcommand_header(description: str) -> None:
    """Render the header with gradient brand logo and right-aligned subtitle.

    The subtitle aligns with where the description text ends.
    """
    _help_console.print()

    # Calculate content width based on description length
    # Description starts at GLOBAL_MARGIN, so end column = GLOBAL_MARGIN + len(description)
    content_end = GLOBAL_MARGIN + len(description)

    # Calculate spacing to align subtitle with content end
    brand_len = len("S E R I X")
    subtitle_len = len(SUBTITLE_TEXT)
    spacing = content_end - GLOBAL_MARGIN - brand_len - subtitle_len

    # Ensure minimum spacing of 2
    spacing = max(spacing, 2)

    # Build the header line
    indent = " " * GLOBAL_MARGIN
    header_text = Text(indent)
    header_text.append_text(create_gradient_brand())
    header_text.append(" " * spacing)
    header_text.append(SUBTITLE_TEXT, style=COLOR_SUBTITLE)

    _help_console.print(header_text)
    _help_console.print()


def _render_description(text: str) -> None:
    """Render the command description with proper indent."""
    indent = " " * GLOBAL_MARGIN
    _help_console.print(f"{indent}[{COLOR_DIM}]{text}[/{COLOR_DIM}]")
    _help_console.print()


def _render_options_from_context(ctx: Context) -> None:
    """Render options with overflow rule (28-char threshold)."""
    indent = " " * GLOBAL_MARGIN
    item_indent = " " * ITEM_INDENT
    desc_indent = " " * 32  # Overflow description indent

    _help_console.print(f"{indent}[{COLOR_DIM}]Options:[/{COLOR_DIM}]")

    table = Table.grid(padding=(0, 2))
    table.add_column(width=FIRST_COL_WIDTH)
    table.add_column()

    for param in ctx.command.params:
        # Skip hidden params
        if getattr(param, "hidden", False):
            continue

        # Get option strings
        opts = getattr(param, "opts", [])
        if not opts:
            continue

        # Build option string (e.g., "--force, -f")
        opt_str = ", ".join(sorted(opts, key=len, reverse=True))

        # Get help text
        help_text = getattr(param, "help", "") or ""

        # Apply overflow rule: 28-char threshold
        effective_len = len(item_indent) + len(opt_str)

        if effective_len >= OVERFLOW_THRESHOLD + ITEM_INDENT:
            # Long option: command on its own line, description on next
            option_styled = f"{item_indent}[{COLOR_COMMAND}]{opt_str}[/{COLOR_COMMAND}]"
            desc_styled = f"[{COLOR_DIM}]{help_text}[/{COLOR_DIM}]"
            _help_console.print(option_styled)
            _help_console.print(f"{desc_indent}{desc_styled}")
        else:
            # Short option: use table for alignment
            option_cell = f"{item_indent}[{COLOR_COMMAND}]{opt_str}[/{COLOR_COMMAND}]"
            desc_cell = f"[{COLOR_DIM}]{help_text}[/{COLOR_DIM}]"
            table.add_row(option_cell, desc_cell)

    # Always add --help option (Click handles it specially, not in params)
    help_option_cell = f"{item_indent}[{COLOR_COMMAND}]--help[/{COLOR_COMMAND}]"
    help_desc_cell = f"[{COLOR_DIM}]Show help and exit[/{COLOR_DIM}]"
    table.add_row(help_option_cell, help_desc_cell)

    _help_console.print(table)
    _help_console.print()


def _render_examples(examples: list[tuple[str, str]]) -> None:
    """Render examples with overflow rule (28-char threshold)."""
    if not examples:
        return

    indent = " " * GLOBAL_MARGIN
    item_indent = " " * ITEM_INDENT
    desc_indent = " " * 32

    _help_console.print(f"{indent}[{COLOR_DIM}]Examples:[/{COLOR_DIM}]")

    # Use a single table for all examples (no blank lines between)
    table = Table.grid(padding=(0, 2))
    table.add_column(width=FIRST_COL_WIDTH)
    table.add_column()

    for command, description in examples:
        command_styled = f"{item_indent}[{COLOR_COMMAND}]{command}[/{COLOR_COMMAND}]"
        desc_styled = f"[{COLOR_DIM}]{description}[/{COLOR_DIM}]"

        effective_len = len(item_indent) + len(command)

        if effective_len >= OVERFLOW_THRESHOLD + ITEM_INDENT:
            # Long command: split to next line (print table first if has rows)
            if table.row_count > 0:
                _help_console.print(table)
                table = Table.grid(padding=(0, 2))
                table.add_column(width=FIRST_COL_WIDTH)
                table.add_column()
            _help_console.print(command_styled)
            _help_console.print(f"{desc_indent}{desc_styled}")
        else:
            # Short command: add to table
            table.add_row(command_styled, desc_styled)

    # Print remaining table rows
    if table.row_count > 0:
        _help_console.print(table)

    _help_console.print()


def _render_docs_section() -> None:
    """Render the Docs section on a single line."""
    indent = " " * GLOBAL_MARGIN

    _help_console.print(
        f"{indent}[{COLOR_DIM}]Docs:[/{COLOR_DIM}] [{COLOR_URL}]{DOCS_URL}[/{COLOR_URL}]"
    )


# =============================================================================
# Base Class for Subcommand Help
# =============================================================================


class SubcommandHelpCommand(TyperCommand):
    """Base class for styled subcommand help.

    Subclasses should override:
    - command_description: str - One-line description of the command
    - examples: list[tuple[str, str]] - List of (command, description) tuples
    """

    command_description: str = ""
    examples: list[tuple[str, str]] = []

    def format_help(self, ctx: Context, formatter: HelpFormatter) -> None:
        """Render styled help matching main help aesthetic."""
        _render_subcommand_header(self.command_description)
        _render_description(self.command_description)
        _render_options_from_context(ctx)
        _render_examples(self.examples)
        _render_docs_section()

    def format_usage(self, ctx: Context, formatter: HelpFormatter) -> None:
        """Override to hide usage line."""
        pass  # Empty - no usage line


# =============================================================================
# Command-Specific Help Classes
# =============================================================================


class InitHelpCommand(SubcommandHelpCommand):
    """Styled help for serix init command."""

    command_description = (
        "Initialize a serix.toml configuration file in your workspace."
    )
    examples = [
        ("serix init", "Create default serix.toml"),
        ("serix init --force", "Replace existing configuration"),
    ]
