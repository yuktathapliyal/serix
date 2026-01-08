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
# Test Command Option Categories (for two-tier help)
# =============================================================================

# Core options shown in --help (14 options)
TEST_CORE_OPTIONS = {
    # Core attack config
    "--goal",
    "-g",
    "--mode",
    "-m",
    "--scenarios",
    "-s",
    "--depth",
    "-d",
    # Provider
    "--provider",
    "-p",
    # Reports
    "--report",
    "-r",
    "--github",
    # HTTP targeting
    "--input-field",
    "--output-field",
    "--headers",
    # Behavior
    "--live",
    "--config",
    "-c",
    "--yes",
    "-y",
    "--verbose",
    "-v",
}

# Category order and options for grouped rendering (dict preserves insertion order)
TEST_CATEGORIES: dict[str, list[str]] = {
    "Core": ["--goal", "--goals-file", "--mode", "--scenarios", "--depth"],
    "Target Identity": ["--name", "--target-id"],
    "Reports & Artifacts": ["--report", "--no-report", "--dry-run", "--github"],
    "HTTP Targeting": [
        "--input-field",
        "--output-field",
        "--headers",
        "--headers-file",
    ],
    "Regression": ["--skip-mitigated", "--skip-regression"],
    "Fuzz Testing": [
        "--fuzz",
        "--fuzz-only",
        "--fuzz-latency",
        "--fuzz-errors",
        "--fuzz-json",
        "--fuzz-probability",
    ],
    "Models": [
        "--provider",
        "--attacker-model",
        "--judge-model",
        "--critic-model",
        "--patcher-model",
        "--analyzer-model",
    ],
    "Behavior": [
        "--live",
        "--exhaustive",
        "--no-patch",
        "--config",
        "--yes",
        "--verbose",
    ],
    "Help": ["--help", "--help-all"],  # Discoverability: show available help options
}

# Categories shown in core --help only
TEST_CORE_CATEGORIES = [
    "Core",
    "Models",
    "Reports & Artifacts",
    "HTTP Targeting",
    "Behavior",
]

# Help options differ between views for discoverability
CORE_HELP_OPTIONS = ["--help"]  # Core view shows only --help
ALL_HELP_OPTIONS = ["--help", "--help-all"]  # Extended view shows both


# =============================================================================
# Section Rendering Functions
# =============================================================================


def _render_subcommand_header(longest_desc_length: int) -> None:
    """Render the header with gradient brand logo and right-aligned subtitle.

    The subtitle end aligns with where the longest option description ends.
    Each command provides its own longest_desc_length for proper alignment.

    Args:
        longest_desc_length: Length of the longest description in this command's help.
    """
    _help_console.print()

    # Calculate content end based on longest option line
    # Table column 1 has width=FIRST_COL_WIDTH (includes item_indent inside the cell)
    # Rich Table.grid(padding=(0, 2)) adds 2 on each side = 4 between columns
    content_end = FIRST_COL_WIDTH + 4 + longest_desc_length

    # Calculate spacing to align subtitle end with content end
    brand_len = len("S E R I X")
    subtitle_len = len(SUBTITLE_TEXT)
    # Subtitle should END at content_end, so it starts at (content_end - subtitle_len)
    # Brand starts at GLOBAL_MARGIN, ends at (GLOBAL_MARGIN + brand_len)
    spacing = content_end - subtitle_len - (GLOBAL_MARGIN + brand_len)

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
    desc_indent = " " * 26  # Overflow description indent

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
    """Render examples with comment-style descriptions."""
    if not examples:
        return

    indent = " " * GLOBAL_MARGIN
    item_indent = " " * ITEM_INDENT

    _help_console.print(f"{indent}[{COLOR_DIM}]Examples:[/{COLOR_DIM}]")

    for command, description in examples:
        # Format: command  # description (comment-style)
        line = (
            f"{item_indent}[{COLOR_COMMAND}]{command}[/{COLOR_COMMAND}]  "
            f"[{COLOR_DIM}]# {description}[/{COLOR_DIM}]"
        )
        _help_console.print(line)

    _help_console.print()


def _render_docs_section() -> None:
    """Render the Docs section on a single line."""
    indent = " " * GLOBAL_MARGIN

    _help_console.print(
        f"{indent}[{COLOR_DIM}]Docs:[/{COLOR_DIM}] [{COLOR_URL}]{DOCS_URL}[/{COLOR_URL}]"
    )


# =============================================================================
# Test Command Two-Tier Help Functions
# =============================================================================


def _render_usage_and_targets() -> None:
    """Render Usage line and target format examples.

    Creates visual hierarchy:
    - Usage line (bold command structure)
    - Target accepts section (dim, informational)

    This separates the command structure from the option categories below.
    """
    indent = " " * GLOBAL_MARGIN
    item_indent = " " * ITEM_INDENT

    # Usage line - shows command structure
    # Note: Escape [options] as \[options] to prevent Rich markup interpretation
    _help_console.print(
        f"{indent}[{COLOR_DIM}]Usage:[/{COLOR_DIM}] "
        f"[{COLOR_COMMAND}]serix test <target> \\[options][/{COLOR_COMMAND}]"
    )
    # No blank line here - keeps Usage and target info visually grouped
    # Target info - subordinate to Usage, explains the <target> placeholder
    _help_console.print(f"{indent}[{COLOR_DIM}]<target> accepts:[/{COLOR_DIM}]")

    # Use same column width as options for "One Lane" alignment
    table = Table.grid(padding=(0, 2))
    table.add_column(width=FIRST_COL_WIDTH)  # 28 chars, descriptions start at col 30
    table.add_column()

    targets = [
        ("Python function", "path/to/file.py:function_name"),
        ("Agent class", "path/to/file.py:ClassName"),
        ("HTTP endpoint", "http://localhost:8000/chat"),
    ]

    # All dim text - informational, not actionable
    for name, example in targets:
        name_styled = f"{item_indent}[{COLOR_DIM}]{name}[/{COLOR_DIM}]"
        example_styled = f"[{COLOR_DIM}]{example}[/{COLOR_DIM}]"
        table.add_row(name_styled, example_styled)

    _help_console.print(table)
    _help_console.print()
    _help_console.print()  # Extra blank line to separate from options below


def _render_help_all_hint() -> None:
    """Render the hint to use --help-all for more options."""
    indent = " " * GLOBAL_MARGIN
    _help_console.print()
    _help_console.print(
        f"{indent}[{COLOR_DIM}]Use [/{COLOR_DIM}]"
        f"[{COLOR_COMMAND}]--help-all[/{COLOR_COMMAND}]"
        f"[{COLOR_DIM}] to see all test options[/{COLOR_DIM}]"
    )
    _help_console.print()  # Blank line before Examples


def _render_help_category(help_opts: list[str]) -> None:
    """Render the Help category with appropriate options for discoverability."""
    indent = " " * GLOBAL_MARGIN
    item_indent = " " * ITEM_INDENT

    _help_console.print(f"{indent}[{COLOR_DIM}]Help:[/{COLOR_DIM}]")

    table = Table.grid(padding=(0, 2))
    table.add_column(width=FIRST_COL_WIDTH)
    table.add_column()

    help_descriptions = {
        "--help": "Show help and exit",
        "--help-all": "Show all options and exit",
    }

    for opt in help_opts:
        opt_styled = f"{item_indent}[{COLOR_COMMAND}]{opt}[/{COLOR_COMMAND}]"
        desc_styled = f"[{COLOR_DIM}]{help_descriptions[opt]}[/{COLOR_DIM}]"
        table.add_row(opt_styled, desc_styled)

    _help_console.print(table)
    _help_console.print()


def _render_option_category(
    category_name: str,
    ctx: Context,
    category_opts: list[str],
    allowed_opts: set[str] | None,
) -> None:
    """Render a single option category with its matching options."""
    indent = " " * GLOBAL_MARGIN
    item_indent = " " * ITEM_INDENT
    desc_indent = " " * 26  # Overflow description indent

    # Find matching params from context
    matching_params = []
    for param in ctx.command.params:
        # Skip hidden params
        if getattr(param, "hidden", False):
            continue

        opts = getattr(param, "opts", [])
        if not opts:
            continue

        # Check if any of the param's opts are in category_opts
        if not any(opt in category_opts for opt in opts):
            continue

        # If allowed_opts is set, check if any opt is allowed
        if allowed_opts is not None:
            if not any(opt in allowed_opts for opt in opts):
                continue

        matching_params.append(param)

    if not matching_params:
        return

    _help_console.print(f"{indent}[{COLOR_DIM}]{category_name}:[/{COLOR_DIM}]")

    table = Table.grid(padding=(0, 2))
    table.add_column(width=FIRST_COL_WIDTH)
    table.add_column()

    for param in matching_params:
        opts = getattr(param, "opts", [])
        opt_str = ", ".join(sorted(opts, key=len, reverse=True))
        help_text = getattr(param, "help", "") or ""

        # Apply overflow rule: 28-char threshold
        effective_len = len(item_indent) + len(opt_str)

        if effective_len >= OVERFLOW_THRESHOLD + ITEM_INDENT:
            # Long option: print table first if has rows, then option on its own line
            if table.row_count > 0:
                _help_console.print(table)
                table = Table.grid(padding=(0, 2))
                table.add_column(width=FIRST_COL_WIDTH)
                table.add_column()
            option_styled = f"{item_indent}[{COLOR_COMMAND}]{opt_str}[/{COLOR_COMMAND}]"
            desc_styled = f"[{COLOR_DIM}]{help_text}[/{COLOR_DIM}]"
            _help_console.print(option_styled)
            _help_console.print(f"{desc_indent}{desc_styled}")
        else:
            # Short option: use table for alignment
            option_cell = f"{item_indent}[{COLOR_COMMAND}]{opt_str}[/{COLOR_COMMAND}]"
            desc_cell = f"[{COLOR_DIM}]{help_text}[/{COLOR_DIM}]"
            table.add_row(option_cell, desc_cell)

    # Print remaining table rows
    if table.row_count > 0:
        _help_console.print(table)

    _help_console.print()


def _render_test_options(ctx: Context, show_all: bool = False) -> None:
    """Render test command options organized by category."""
    # Get category list based on mode
    if show_all:
        categories = TEST_CATEGORIES
    else:
        categories = {
            k: v for k, v in TEST_CATEGORIES.items() if k in TEST_CORE_CATEGORIES
        }

    # Filter options for core mode
    allowed_opts = None if show_all else TEST_CORE_OPTIONS

    for category_name, category_opts in categories.items():
        # Special handling for Help category (discoverability)
        if category_name == "Help":
            help_opts = ALL_HELP_OPTIONS if show_all else CORE_HELP_OPTIONS
            _render_help_category(help_opts)
            continue

        _render_option_category(category_name, ctx, category_opts, allowed_opts)


# =============================================================================
# Base Class for Subcommand Help
# =============================================================================


class SubcommandHelpCommand(TyperCommand):
    """Base class for styled subcommand help.

    Subclasses should override:
    - command_description: str - One-line description of the command
    - examples: list[tuple[str, str]] - List of (command, description) tuples
    - longest_desc_length: int - Length of longest description (for subtitle alignment)
    """

    command_description: str = ""
    examples: list[tuple[str, str]] = []
    longest_desc_length: int = 30  # Default, subclasses should override

    def format_help(self, ctx: Context, formatter: HelpFormatter) -> None:
        """Render styled help matching main help aesthetic."""
        _render_subcommand_header(self.longest_desc_length)
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
    # The description line (61 chars) ends at position 63 (GLOBAL_MARGIN + 61)
    # which is longer than any table row (22 + 4 + 30 = 56).
    # To align subtitle with description end: 63 = 22 + 4 + X, so X = 37
    longest_desc_length = 37


class TestHelpCommand(SubcommandHelpCommand):
    """Styled help for serix test with two-tier support.

    - `serix test --help` shows core options only
    - `serix test --help-all` shows all options organized by category
    """

    command_description = (
        "Run adversarial attacks against your agent and get actionable fixes."
    )

    examples = [
        ('serix test agent.py:main --goal "reveal secrets"', "Basic security test"),
        ('serix test agent.py --goal "A" --goal "B"', "Multiple goals"),
        ("serix test http://localhost:8000/chat --github", "HTTP endpoint with CI"),
    ]
    # Longest: "Model for vulnerability analysis (default: gpt-4o-mini)" = 55 chars
    longest_desc_length = 55

    def format_help(self, ctx: Context, formatter: HelpFormatter) -> None:
        """Render styled help with optional extended options."""
        import sys

        show_all = "--help-all" in sys.argv

        _render_subcommand_header(self.longest_desc_length)
        _render_description(self.command_description)
        _render_usage_and_targets()  # Usage line + target format examples
        _render_test_options(ctx, show_all=show_all)

        if not show_all:
            _render_help_all_hint()

        _render_examples(self.examples)
        _render_docs_section()
