"""Serix rendering helpers - consistent output formatting.

Provides composable rendering primitives for Serix's premium CLI experience.
All output goes through these helpers to ensure visual consistency.
"""

from __future__ import annotations

from rich.console import Console

from serix.ui.theme import BULLET, FAILURE, PREFIX, SEPARATOR, SUCCESS, TAGLINE


def banner(console: Console, version: str, show: bool = True) -> None:
    """Render the Serix banner.

    Format: SERIX  v{version} - The Immune System for AI Agents

    Args:
        console: Rich console to print to
        version: Version string (e.g., "0.2.6")
        show: If False, do nothing (for conditional display)
    """
    if not show:
        return

    console.print(
        f"[serix.brand]SERIX[/]  [serix.muted]v{version}[/] {BULLET} {TAGLINE}"
    )
    # Placeholder for future description line (currently disabled to avoid redundancy)
    # console.print(
    #     "[serix.muted]AI agent security testing with recording, replay, and fuzzing.[/]"
    # )
    rule(console)


def rule(console: Console) -> None:
    """Render a thin separator line.

    Args:
        console: Rich console to print to
    """
    console.print(f"[serix.rule]{SEPARATOR}[/]")


def kv(console: Console, label: str, value: str, label_width: int = 6) -> None:
    """Render a key/value line with prefix.

    Format: › Label:  value (with consistent column alignment)

    Args:
        console: Rich console to print to
        label: The key/label (plain white text)
        value: The value (muted grey)
        label_width: Width to pad label to (default: 6 for "Target")
    """
    padded_label = f"{label}:".ljust(label_width + 1)
    console.print(f"[serix.muted]{PREFIX}[/] {padded_label} [serix.muted]{value}[/]")


def section_header(console: Console, title: str, subtitle: str = "") -> None:
    """Render SERIX | Section Title header.

    Format: SERIX  |  Section Title

    Args:
        console: Rich console to print to
        title: Section title (e.g., "Immune Check")
        subtitle: Optional subtitle (not currently used)
    """
    console.print(f"[serix.brand]SERIX[/]  [serix.muted]|[/]  {title}")
    rule(console)


def result_line(console: Console, passed: bool, message: str) -> None:
    """Render a pass/fail result line.

    Format: ✓ message (green) or ✗ message (red)

    Args:
        console: Rich console to print to
        passed: Whether the result is pass/success
        message: Result message to display
    """
    if passed:
        icon = f"[serix.ok]{SUCCESS}[/]"
    else:
        icon = f"[serix.bad]{FAILURE}[/]"
    console.print(f"{icon} {message}")


def progress_line(
    console: Console,
    current: int,
    total: int,
    label: str,
    status: str,
    passed: bool | None = None,
) -> None:
    """Render a progress line with [X/Y] format.

    Format: [1/5] strategy_name: ✓ defended

    Args:
        console: Rich console to print to
        current: Current item number (1-indexed)
        total: Total items
        label: Item label (e.g., strategy name)
        status: Status text (e.g., "defended", "exploited")
        passed: If True=green, False=red, None=neutral
    """
    if passed is True:
        icon = f"[serix.ok]{SUCCESS}[/]"
        status_styled = f"[serix.ok]{status}[/]"
    elif passed is False:
        icon = f"[serix.bad]{FAILURE}[/]"
        status_styled = f"[serix.bad]{status}[/]"
    else:
        icon = ""
        status_styled = f"[serix.muted]{status}[/]"

    console.print(
        f"[serix.muted][{current}/{total}][/] {label}: {icon} {status_styled}"
    )


def command_list(console: Console, commands: list[tuple[str, str]]) -> None:
    """Render aligned command list for help.

    Format:
    Commands:
      › command1  Description 1
      › command2  Description 2

    Args:
        console: Rich console to print to
        commands: List of (name, description) tuples
    """
    if not commands:
        return

    max_name = max(len(name) for name, _ in commands)
    console.print("[serix.muted]Commands:[/]")
    for name, desc in commands:
        console.print(
            f"  [serix.muted]{PREFIX}[/] [serix.label]{name:<{max_name}}[/]  [serix.muted]{desc}[/]"
        )


def option_list(console: Console, options: list[tuple[str, str, str]]) -> None:
    """Render aligned option list for help.

    Format:
    Options:
      › --option, -o  TYPE  Description

    Args:
        console: Rich console to print to
        options: List of (flags, type, description) tuples
    """
    if not options:
        return

    max_flags = max(len(flags) for flags, _, _ in options)
    max_type = max(len(opt_type) for _, opt_type, _ in options)

    console.print("[serix.muted]Options:[/]")
    for flags, opt_type, desc in options:
        type_part = f"[serix.muted]{opt_type:<{max_type}}[/]" if opt_type else ""
        console.print(
            f"  [serix.muted]{PREFIX}[/] [serix.label]{flags:<{max_flags}}[/]  {type_part}  "
            f"[serix.muted]{desc}[/]"
        )


def calc_option_widths(
    all_options: list[list[tuple[str, str, str]]]
) -> tuple[int, int]:
    """Calculate global column widths across multiple option groups.

    Args:
        all_options: List of option groups, each containing (flags, type, desc) tuples

    Returns:
        Tuple of (max_flags_width, max_type_width)
    """
    flat = [opt for group in all_options for opt in group]
    if not flat:
        return (0, 0)
    max_flags = max(len(flags) for flags, _, _ in flat)
    max_type = max(len(opt_type) for _, opt_type, _ in flat)
    return (max_flags, max_type)


def option_group(
    console: Console,
    title: str,
    options: list[tuple[str, str, str]],
    col_widths: tuple[int, int] | None = None,
    highlight_flags: set[str] | None = None,
) -> None:
    """Render a titled group of options for subcommand help.

    Format:
    Title:
      › --flag, -f  TYPE  Description

    Args:
        console: Rich console to print to
        title: Group title (e.g., "Attack Configuration")
        options: List of (flags, type, description) tuples
        col_widths: Optional (max_flags, max_type) for global alignment
        highlight_flags: Set of flag strings to highlight in cyan (others are default)
    """
    if not options:
        return

    if col_widths:
        max_flags, max_type = col_widths
    else:
        max_flags = max(len(flags) for flags, _, _ in options)
        max_type = max(len(opt_type) for _, opt_type, _ in options)

    console.print(f"[serix.brand]{title}:[/]")
    for flags, opt_type, desc in options:
        type_part = (
            f"[serix.muted]{opt_type:<{max_type}}[/]" if opt_type else " " * max_type
        )

        # Highlight only specified flags, others are default color
        if highlight_flags and flags in highlight_flags:
            flag_style = "serix.label"
        else:
            flag_style = ""  # default terminal color

        if flag_style:
            flags_part = f"[{flag_style}]{flags:<{max_flags}}[/{flag_style}]"
        else:
            flags_part = f"{flags:<{max_flags}}"

        console.print(
            f"  [serix.muted]{PREFIX}[/] {flags_part}  {type_part}  "
            f"[serix.muted]{desc}[/]"
        )


def target_list(
    console: Console,
    targets: list[tuple[str, str]],
    col_width: int | None = None,
) -> None:
    """Render aligned target type list for help.

    Format:
    Targets:
      › Python function   path/to/file.py:function_name
      › Agent class       path/to/file.py:ClassName

    Args:
        console: Rich console to print to
        targets: List of (label, example) tuples
        col_width: Optional first column width for global alignment
    """
    if not targets:
        return

    max_label = col_width if col_width else max(len(label) for label, _ in targets)

    console.print("[serix.brand]Targets:[/]")
    for label, example in targets:
        console.print(
            f"  [serix.muted]{PREFIX}[/] {label:<{max_label}}  [serix.muted]{example}[/]"
        )


def status_badge(console: Console, status: str, style: str = "serix.muted") -> None:
    """Render a status badge inline.

    Args:
        console: Rich console to print to
        status: Status text (e.g., "EXPLOITED", "DEFENDED")
        style: Rich style to apply
    """
    console.print(f"[{style}]{status}[/{style}]", end="")


def error(console: Console, message: str, details: str = "") -> None:
    """Render an error message.

    Format: ✗ Error: message

    Args:
        console: Rich console to print to
        message: Main error message
        details: Optional additional details
    """
    console.print(f"[serix.bad]{FAILURE} Error:[/] {message}")
    if details:
        console.print(f"  [serix.muted]{details}[/]")


def warning(console: Console, message: str) -> None:
    """Render a warning message.

    Format: ⚠ Warning: message

    Args:
        console: Rich console to print to
        message: Warning message
    """
    console.print(f"[serix.warn]Warning:[/] {message}")


def success(console: Console, message: str) -> None:
    """Render a success message.

    Format: ✓ message

    Args:
        console: Rich console to print to
        message: Success message
    """
    console.print(f"[serix.ok]{SUCCESS}[/] {message}")


def muted(console: Console, message: str) -> None:
    """Render muted/secondary text.

    Args:
        console: Rich console to print to
        message: Message to display
    """
    console.print(f"[serix.muted]{message}[/]")


def scores_inline(console: Console, scores: dict[str, int]) -> None:
    """Render scores on a single horizontal line.

    Format: Scores: Overall 0 • Safety 0 • Compliance 0 • Info Leakage 0

    Args:
        console: Rich console to print to
        scores: Dictionary of score name to value (0-100)
    """
    parts = [f"{name} {value}" for name, value in scores.items()]
    line = f" {BULLET} ".join(parts)
    console.print(f"[serix.label]Scores:[/] {line}")


def persona_outcomes(
    console: Console,
    outcomes: list[dict[str, str | bool | int]],
) -> None:
    """Render persona outcomes as a compact bullet list.

    Format:
    Persona Outcomes:
    • Jailbreaker   → EXPLOITED (Turn 4)
    • Extractor     → defended

    Args:
        console: Rich console to print to
        outcomes: List of dicts with 'persona', 'success', and optionally 'turns' keys
    """
    if not outcomes:
        return

    console.print("[serix.label]Persona Outcomes:[/]")

    # Calculate max persona name length for alignment
    max_name = max(len(str(o.get("persona", ""))) for o in outcomes)

    for outcome in outcomes:
        persona = str(outcome.get("persona", "unknown"))
        success = outcome.get("success", False)
        turns = outcome.get("turns", 0)

        if success:
            status = "[serix.bad]EXPLOITED[/]"
            turns_info = f" (Turn {turns})" if turns else ""
        else:
            status = "[serix.muted]defended[/]"
            turns_info = ""

        console.print(f"{BULLET} {persona:<{max_name}}  → {status}{turns_info}")


def cost_estimate(
    console: Console,
    goals: int,
    personas: int,
    turns: int,
) -> None:
    """Render cost estimate block.

    Format: Cost Estimate: 1 goal(s) x 4 persona(s) x 4 turn(s) = ~16 API calls

    Args:
        console: Rich console to print to
        goals: Number of goals to test
        personas: Number of personas per goal
        turns: Max turns per persona
    """
    total = goals * personas * turns
    console.print(
        f"Cost Estimate: "
        f"[serix.muted]{goals} goal(s) x {personas} persona(s) x {turns} turn(s) = ~{total} API calls[/]"
    )
