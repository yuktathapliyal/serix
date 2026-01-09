"""
Serix v2 - Console Renderer

All Rich formatting for CLI output.

Law 2 Compliance: This is the ONLY place where Rich formatting
is allowed in serix_v2. Commands call these functions for display.

Guardrail 5: Display Isolation - All rich/tables/bars go HERE.
"""

import atexit
from datetime import datetime, timezone

from rich.console import Console, Group
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from serix_v2.cli.theme import (
    COLOR_COMMAND,
    COLOR_DIM,
    COLOR_ERROR,
    COLOR_GRADE,
    COLOR_SUBTITLE,
    COLOR_SUCCESS,
    COLOR_WARNING,
    CONTENT_WIDTH,
    GLOBAL_MARGIN,
    SUBTITLE_TEXT,
    create_gradient_brand,
)
from serix_v2.core.contracts import (
    AttackResult,
    AttackStatus,
    AttackTransition,
    CampaignResult,
    Grade,
    ProgressEvent,
    ProgressPhase,
    ToolRecommendation,
)
from serix_v2.services.status import StatusSummary, TargetStatus

console = Console()

# Ensure cursor is restored on exit (fixes Ctrl+C leaving cursor hidden)
atexit.register(console.show_cursor)

# OWASP LLM Top 10 human-readable titles
OWASP_TITLES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Info Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}


# =============================================================================
# Deduplication Helpers (Phase 12O - Pentest Quality)
# =============================================================================


def _make_vuln_key(
    goal: str,
    strategy_id: str,
    owasp_code: str | None,
) -> tuple[str, str, str | None]:
    """Create vulnerability dedup key (3-tuple)."""
    return (goal, strategy_id, owasp_code)


def _keys_match(
    key1: tuple[str, str, str | None],
    key2: tuple[str, str, str | None],
) -> bool:
    """Check if two vulnerability keys match.

    If either has owasp_code=None, fall back to 2-tuple matching.
    """
    goal1, strategy1, owasp1 = key1
    goal2, strategy2, owasp2 = key2

    if goal1 != goal2 or strategy1 != strategy2:
        return False

    # If either is None, 2-tuple match is sufficient
    if owasp1 is None or owasp2 is None:
        return True

    # Both have OWASP codes, must match
    return owasp1 == owasp2


def _get_exploit_categories(
    new_exploits: list[AttackResult],
    regression_exploits: list[AttackTransition],
) -> str:
    """Build category string for headline."""
    from collections import Counter

    categories: Counter[str] = Counter()

    # New exploits
    for a in new_exploits:
        if a.analysis:
            title = OWASP_TITLES.get(a.analysis.owasp_code, "Unknown")
            categories[title] += 1

    # Regression exploits
    for t in regression_exploits:
        if t.owasp_code:
            title = OWASP_TITLES.get(t.owasp_code, "Unknown")
            categories[title] += 1

    if not categories:
        return "Unknown"

    # Format: "Info Disclosure (2), Injection" or "Info Disclosure, +2 more"
    if len(categories) <= 2:
        parts = []
        for cat, count in categories.most_common():
            if count > 1:
                parts.append(f"{cat} ({count})")
            else:
                parts.append(cat)
        return ", ".join(parts)
    else:
        top = categories.most_common(1)[0]
        remaining = len(categories) - 1
        return f"{top[0]}, +{remaining} more"


def _format_exploited_since(exploited_since: datetime | None) -> str:
    """Format the exploited_since date for display."""
    if exploited_since is None:
        return ""

    today = datetime.now(timezone.utc).date()
    exploit_date = exploited_since.date()

    if exploit_date == today:
        return f"Re-introduced on {exploit_date.strftime('%b %d, %Y')}"
    else:
        return f"Unpatched since {exploit_date.strftime('%b %d, %Y')}"


def _score_to_grade(score: int) -> Grade:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return Grade.A
    elif score >= 80:
        return Grade.B
    elif score >= 70:
        return Grade.C
    elif score >= 60:
        return Grade.D
    else:
        return Grade.F


# =============================================================================
# Init Command Renderers
# =============================================================================


def render_init_success(path: str, version: str) -> None:
    """Render successful init message."""
    console.print()
    console.print(f"  [{COLOR_SUCCESS}]✓[/{COLOR_SUCCESS}] Created {path}")
    console.print()
    console.print("  [{COLOR_DIM}]What's next?[/{COLOR_DIM}]")
    console.print("    1. Edit serix.toml to configure your target")
    console.print(
        "    2. Run [{COLOR_DIM}]serix test[/{COLOR_DIM}] to start security testing"
    )
    console.print()
    console.print(
        "  [{COLOR_DIM}]Docs[/{COLOR_DIM}]  https://github.com/yuktathapliyal/serix"
    )
    console.print()


def render_init_exists(path: str) -> None:
    """Render warning when config already exists."""
    console.print()
    console.print(f"  [{COLOR_WARNING}]⚠[/{COLOR_WARNING}] {path} already exists")
    console.print()
    console.print("  To overwrite, run:")
    console.print("    [{COLOR_DIM}]serix init --force[/{COLOR_DIM}]")
    console.print()


def render_init_replaced(path: str, backup_path: str) -> None:
    """Render message when config was replaced."""
    console.print()
    console.print(f"  [{COLOR_SUCCESS}]✓[/{COLOR_SUCCESS}] Replaced {path}")
    console.print(f"    Backup saved to {backup_path}")
    console.print()
    console.print("  [{COLOR_DIM}]What's next?[/{COLOR_DIM}]")
    console.print("    1. Edit serix.toml to configure your target")
    console.print(
        "    2. Run [{COLOR_DIM}]serix test[/{COLOR_DIM}] to start security testing"
    )
    console.print()


# =============================================================================
# Status Command Renderers
# =============================================================================


def render_status_table(summary: StatusSummary, verbose: bool = False) -> None:
    """Render status summary with health bars."""
    console.print()
    console.print(
        "  [bold]S E R I X   S T A T U S[/bold]                        Attack Library"
    )
    console.print()

    if summary.total_targets == 0:
        render_no_targets_found()
        return

    # Summary line
    console.print(f"  Targets    {summary.total_targets}")
    console.print(f"  Attacks    {summary.total_attacks} total")

    if summary.total_attacks > 0:
        health_pct = int((summary.total_defended / summary.total_attacks) * 100)
        console.print(f"  Posture    {health_pct}% defended")

    console.print()

    # Per-target breakdown
    for target in summary.targets:
        _render_target_row(target, verbose)

    console.print()
    console.print(
        "  [{COLOR_DIM}]View details:[/{COLOR_DIM}] serix status --name <alias> -v"
    )
    console.print()


def render_single_target_status(target: TargetStatus, verbose: bool = False) -> None:
    """Render detailed status for a single target."""
    console.print()
    console.print(
        f"  [bold]S E R I X   S T A T U S[/bold]                  {target.name or target.target_id}"
    )
    console.print()
    console.print(f"  Target ID    {target.target_id}")
    console.print(f"  Locator      {target.locator}")
    console.print(f"  Type         {target.target_type}")

    if target.created_at:
        console.print(f"  Created      {target.created_at.strftime('%b %d, %Y')}")
    if target.last_tested:
        console.print(
            f"  Last run     {target.last_tested.strftime('%b %d, %Y · %H:%M')}"
        )

    # Health bar
    health_bar = _create_health_bar(target.health_score)
    console.print(
        f"  Health       {health_bar}  {int(target.health_score)}%  GRADE {target.grade}"
    )
    console.print()


def render_no_targets_found() -> None:
    """Render message when no targets in attack library."""
    panel = Panel(
        "\n           No targets in attack library\n\n"
        "   Run serix test to start testing an agent\n",
        border_style=COLOR_DIM,
    )
    console.print()
    console.print(panel)
    console.print()
    console.print("  [{COLOR_DIM}]Get started:[/{COLOR_DIM}]")
    console.print('    serix test agent.py:my_agent --goal "reveal secrets"')
    console.print()


def render_target_not_found(
    name: str | None = None, target_id: str | None = None
) -> None:
    """Render error when target not found."""
    identifier = name or target_id
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] Target not found")
    console.print()
    console.print(f"  No target with {'name' if name else 'ID'}: {identifier}")
    console.print()
    console.print("  [{COLOR_DIM}]View all:[/{COLOR_DIM}] serix status")
    console.print()


def _render_target_row(target: TargetStatus, verbose: bool) -> None:
    """Render a single target row in status table."""
    # Name or target_id
    header = target.name or target.locator[:40]
    console.print(
        f"  [bold]{header}[/bold]"
        + " " * max(0, 45 - len(header))
        + f"[{COLOR_DIM}]{target.target_id}[/{COLOR_DIM}]"
    )
    console.print()

    # Stats
    console.print(
        f"  Attacks      {target.total_attacks} total · {target.exploited} exploited · {target.defended} defended"
    )

    # Last run
    if target.last_tested:
        console.print(
            f"  Last run     {target.last_tested.strftime('%b %d, %Y · %H:%M')}"
        )

    # Health bar
    health_bar = _create_health_bar(target.health_score)
    grade_color = _get_grade_color(target.grade)
    console.print(
        f"  Health       {health_bar}  {int(target.health_score)}%  [{grade_color}]GRADE {target.grade}[/{grade_color}]"
    )
    console.print()
    console.print()


def _create_health_bar(percent: float, width: int = 20) -> str:
    """Create a health bar string."""
    filled = int((percent / 100) * width)
    empty = width - filled

    # Color based on percentage (using brand-aligned colors)
    if percent >= 80:
        color = COLOR_SUCCESS
    elif percent >= 60:
        color = COLOR_WARNING
    else:
        color = COLOR_ERROR

    return f"[{color}]{'█' * filled}[/{color}][{COLOR_DIM}]{'░' * empty}[/{COLOR_DIM}]"


def _get_grade_color(grade: str) -> str:
    """Get color for grade display (brand-aligned)."""
    if grade == "A":
        return COLOR_SUCCESS
    elif grade == "B":
        return COLOR_SUCCESS
    elif grade == "C":
        return COLOR_WARNING
    elif grade == "D":
        return COLOR_WARNING
    else:
        return COLOR_ERROR


# =============================================================================
# Test Command Renderers
# =============================================================================


def render_campaign_header(
    target_path: str,
    target_id: str,
    goals: list[str],
    mode: str,
    depth: int,
    provider: str | None = None,
    provider_auto_detected: bool = False,
) -> None:
    """Render campaign header with target info."""
    console.print()

    # Build header with gradient brand (matches help screens)
    # Spacing = CONTENT_WIDTH - GLOBAL_MARGIN - brand_len - subtitle_len
    brand_len = len("S E R I X")
    subtitle_len = len(SUBTITLE_TEXT)
    spacing = CONTENT_WIDTH - GLOBAL_MARGIN - brand_len - subtitle_len

    indent = " " * GLOBAL_MARGIN
    header_text = Text(indent)
    header_text.append_text(create_gradient_brand())
    header_text.append(" " * spacing)
    header_text.append(SUBTITLE_TEXT, style=COLOR_SUBTITLE)

    console.print(header_text)
    console.print()
    # 4-space indent + 25-char label = content at column 30 (balanced visual layout)
    # Labels and values in COLOR_DIM (matches help screen pattern)
    console.print(
        f"    [{COLOR_DIM}]{'Target':<25}[/{COLOR_DIM}] [{COLOR_DIM}]{target_path}[/{COLOR_DIM}]"
    )
    console.print(
        f"    [{COLOR_DIM}]{'ID':<25}[/{COLOR_DIM}] [{COLOR_DIM}]{target_id}[/{COLOR_DIM}]"
    )

    # Provider line (Phase 13)
    if provider:
        provider_suffix = " (auto)" if provider_auto_detected else ""
        console.print(
            f"    [{COLOR_DIM}]{'Provider':<25}[/{COLOR_DIM}] [{COLOR_DIM}]{provider}{provider_suffix}[/{COLOR_DIM}]"
        )

    if len(goals) == 1:
        console.print(
            f"    [{COLOR_DIM}]{'Goal':<25}[/{COLOR_DIM}] [{COLOR_DIM}]{goals[0]}[/{COLOR_DIM}]"
        )
    else:
        console.print(
            f"    [{COLOR_DIM}]{'Goals':<25}[/{COLOR_DIM}] [{COLOR_DIM}]{len(goals)} objectives[/{COLOR_DIM}]"
        )
        for goal in goals[:3]:  # Show first 3
            console.print(
                f"    {'':<25} [{COLOR_DIM}]· {goal[:50]}{'...' if len(goal) > 50 else ''}[/{COLOR_DIM}]"
            )
        if len(goals) > 3:
            console.print(
                f"    {'':<25} [{COLOR_DIM}]· ... and {len(goals) - 3} more[/{COLOR_DIM}]"
            )

    console.print(
        f"    [{COLOR_DIM}]{'Mode':<25}[/{COLOR_DIM}] [{COLOR_DIM}]{mode} · depth {depth}[/{COLOR_DIM}]"
    )
    console.print()


def render_campaign_result(result: CampaignResult, verbose: bool = False) -> None:
    """Render complete campaign result."""
    # Header already shown before run in test_cmd.py

    # Regression results FIRST (matches execution order - regression runs before new attacks)
    if result.regression_ran and result.regression_replayed > 0:
        render_regression_result(
            replayed=result.regression_replayed,
            still_exploited=result.regression_still_exploited,
            now_defended=result.regression_now_defended,
        )

    # New attack results by persona
    _render_attack_results(result.attacks, verbose)

    # Grade panel (with deduplication)
    render_grade_panel(
        result.score.grade,
        result.score.overall_score,
        result.attacks,
        regression_transitions=result.regression_transitions,
    )

    # Findings (with deduplication + merge)
    exploits = [a for a in result.attacks if a.success]
    has_regression_exploits = any(
        t.current_status == AttackStatus.EXPLOITED
        for t in result.regression_transitions
    )
    if exploits or has_regression_exploits:
        render_findings(exploits, result.regression_transitions)

    # Footer
    console.print()
    console.print(
        f"  [{COLOR_DIM}]Duration[/{COLOR_DIM}]   [{COLOR_DIM}]{result.duration_seconds:.1f}s[/{COLOR_DIM}]",
        highlight=False,
    )
    # Report path is printed by test_cmd.py after report generation


def _render_attack_results(attacks: list[AttackResult], verbose: bool) -> None:
    """Render attack results with health bars."""
    console.print()
    console.print("  [bold white]New Attacks[/bold white]")
    console.print()

    # Calculate max turns for proportional bar display
    max_turns = max((len(a.turns) for a in attacks), default=1)

    for attack in attacks:
        # Fixed-width status (9 chars) so "turn X" aligns
        status_word = "EXPLOITED" if attack.success else "DEFENDED"
        status_color = COLOR_ERROR if attack.success else COLOR_SUCCESS
        status_text = f"[{status_color}]{status_word:<9}[/{status_color}]"
        turns_text = f"[{COLOR_DIM}]turn {len(attack.turns)}[/{COLOR_DIM}]"

        # Progress bar (brand-aligned colors)
        if attack.success:
            # Exploited: show proportion of max depth
            proportion = len(attack.turns) / max_turns
            filled = max(1, int(proportion * 20))  # At least 1 block
            bar = f"[{COLOR_ERROR}]{'█' * filled}[/{COLOR_ERROR}][{COLOR_DIM}]{'░' * (20 - filled)}[/{COLOR_DIM}]"
        else:
            # Defended: full bar
            bar = f"[{COLOR_SUCCESS}]{'█' * 20}[/{COLOR_SUCCESS}]"

        persona_name = (
            attack.persona.value.capitalize() if attack.persona else "Unknown"
        )
        # 4-space indent + 25-char label = content at column 30
        console.print(
            f"    [{COLOR_COMMAND}]{persona_name:<25}[/{COLOR_COMMAND}] {bar} {status_text} {turns_text}"
        )

        # Verbose: show turns
        if verbose and attack.turns:
            console.print()
            for i, turn in enumerate(attack.turns, 1):
                console.print(f"    Turn {i}")
                console.print()
                console.print("    [bold]Attacker[/bold]")
                for line in turn.payload.split("\n")[:3]:
                    console.print(f"    {line[:60]}")
                console.print()
                console.print("    [bold]Target[/bold]")
                for line in turn.response.split("\n")[:3]:
                    console.print(f"    {line[:60]}")
                console.print()

    console.print()


def render_grade_panel(
    grade: Grade,
    score: int,
    attacks: list[AttackResult],
    regression_transitions: list[AttackTransition] | None = None,
) -> None:
    """Render grade panel with pentest-quality deduplication."""
    regression_transitions = regression_transitions or []

    # Build list of regression vulnerability keys (3-tuple)
    regression_keys: list[tuple[str, str, str | None]] = []
    regression_exploits: list[AttackTransition] = []
    for t in regression_transitions:
        if t.current_status == AttackStatus.EXPLOITED:
            key = _make_vuln_key(t.goal, t.strategy_id, t.owasp_code)
            regression_keys.append(key)
            regression_exploits.append(t)

    # Count NEW exploits (only those NOT matching any regression key)
    new_exploits: list[AttackResult] = []
    for a in attacks:
        if a.success:
            owasp = a.analysis.owasp_code if a.analysis else None
            key = _make_vuln_key(
                a.goal, a.persona.value if a.persona else "unknown", owasp
            )
            # Check if this matches ANY regression key
            if not any(_keys_match(key, rk) for rk in regression_keys):
                new_exploits.append(a)
            # If it matches, it's confirmation of regression, not new

    # Unique vulnerability counts
    unique_regression = len(regression_exploits)
    unique_new = len(new_exploits)
    total_unique_exploits = unique_regression + unique_new

    # Calculate score from total tests
    total_tests = len(attacks) + len(regression_transitions)
    total_defended = total_tests - total_unique_exploits
    actual_score = int((total_defended / total_tests) * 100) if total_tests > 0 else 100
    actual_grade = _score_to_grade(actual_score)

    # Build adaptive headline
    if total_unique_exploits == 0:
        headline = "All attacks defended"
    else:
        categories = _get_exploit_categories(new_exploits, regression_exploits)
        s = "s" if total_unique_exploits > 1 else ""
        headline = f"{total_unique_exploits} exploit{s} — {categories}"

    # Build breakdown (only show non-zero)
    breakdown_parts = []
    if unique_new > 0:
        breakdown_parts.append(f"{unique_new} new")
    if unique_regression > 0:
        breakdown_parts.append(f"{unique_regression} regression")
    breakdown = " · ".join(breakdown_parts) if breakdown_parts else ""

    # Health bar (colored to match grade)
    filled = actual_score // 5
    empty = 20 - filled
    bar_color = _get_grade_color(actual_grade.value)

    # Render (all center-aligned)
    content = Text(justify="center")
    content.append(f"GRADE {actual_grade.value}", style=f"bold {COLOR_GRADE}")
    content.append("\n\n")
    content.append(headline)
    content.append("\n\n")
    if breakdown:
        content.append(breakdown, style=COLOR_DIM)
        content.append("\n\n")
    content.append("█" * filled, style=bar_color)
    content.append("░" * empty, style=COLOR_DIM)
    content.append(f"\n{actual_score}%\n", style=COLOR_DIM)

    # Center panel relative to attack bar lines
    panel = Panel(content, border_style=COLOR_DIM, width=40)
    console.print(Padding(panel, (0, 0, 0, 16)))


def _get_fix_phrases(recommendations: list[ToolRecommendation]) -> list[str]:
    """Extract clean noun phrases from recommendations.

    Returns list of capitalized 2-word phrases like "Output filtering".
    Stops before prepositions/connectors for cleaner display.
    """
    if not recommendations:
        return []

    stop_words = {"to", "for", "-", "(", "and", "with", "using", "by"}

    phrases = []
    for rec in recommendations[:3]:  # Max 3 fixes shown
        text = rec.recommendation
        # Remove common prefixes
        for prefix in [
            "Add ",
            "Implement ",
            "Use ",
            "Deploy ",
            "Configure ",
            "Create ",
        ]:
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break

        # Take words until we hit a stop word
        words = []
        for word in text.split()[:4]:  # Max 4 words to scan
            if word.lower().rstrip(",.-") in stop_words:
                break
            words.append(word.rstrip(",.-"))
            if len(words) >= 2:  # Stop at 2 words
                break

        phrase = " ".join(words)
        if phrase:
            phrases.append(phrase.capitalize())

    return phrases


def render_findings(
    exploits: list[AttackResult],
    regression_transitions: list[AttackTransition] | None = None,
) -> None:
    """Render findings with pentest-quality deduplication (3-tuple keys)."""
    regression_transitions = regression_transitions or []

    # Build regression lookup: list of (key, transition) pairs
    regression_items: list[tuple[tuple[str, str, str | None], AttackTransition]] = []
    for t in regression_transitions:
        if t.current_status == AttackStatus.EXPLOITED:
            key = _make_vuln_key(t.goal, t.strategy_id, t.owasp_code)
            regression_items.append((key, t))

    # Track which regression items were merged (by index)
    merged_regression_indices: set[int] = set()

    console.print()
    console.print("  [bold white]Findings[/bold white]")
    console.print()

    # Process new exploits
    for attack in exploits:
        if not attack.success:
            continue
        owasp = attack.analysis.owasp_code if attack.analysis else None
        key = _make_vuln_key(
            attack.goal, attack.persona.value if attack.persona else "unknown", owasp
        )

        # Find matching regression (if any)
        matched_idx = None
        for idx, (rk, _) in enumerate(regression_items):
            if _keys_match(key, rk) and idx not in merged_regression_indices:
                matched_idx = idx
                break

        if matched_idx is not None:
            # MERGED: New attack confirms regression - show as REGRESSION
            merged_regression_indices.add(matched_idx)
            _render_merged_finding(attack, regression_items[matched_idx][1])
        else:
            # Truly new exploit
            _render_new_finding(attack)

    # Render remaining regression exploits (not confirmed by new attack)
    for idx, (_, transition) in enumerate(regression_items):
        if idx not in merged_regression_indices:
            _render_regression_finding(transition)


def _render_merged_finding(attack: AttackResult, transition: AttackTransition) -> None:
    """Render merged finding - new attack confirmed regression."""
    owasp = (
        attack.analysis.owasp_code
        if attack.analysis
        else transition.owasp_code or "LLM01"
    )
    owasp_title = OWASP_TITLES.get(owasp, "Unknown Vulnerability")
    persona = (
        attack.persona.value.capitalize()
        if attack.persona
        else transition.strategy_id.capitalize()
    )
    severity_text = "CRITICAL" if owasp == "LLM01" else "HIGH"
    severity_style = f"bold {COLOR_ERROR}" if owasp == "LLM01" else COLOR_ERROR

    # Header with REGRESSION tag
    console.print(
        f"    [{COLOR_COMMAND}]{owasp_title}[/{COLOR_COMMAND}] [{COLOR_DIM}]{owasp}[/{COLOR_DIM}] · "
        f"[{COLOR_COMMAND}]{persona}[/{COLOR_COMMAND}] · [{severity_style}]{severity_text}[/{severity_style}] · "
        f"[{COLOR_ERROR}]REGRESSION[/{COLOR_ERROR}]"
    )

    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=25)
    grid.add_column()

    # Show lifecycle date
    date_text = _format_exploited_since(transition.exploited_since)
    if date_text:
        grid.add_row("", f"[{COLOR_DIM}]{date_text}[/{COLOR_DIM}]")

    # Use fixes from new attack analysis (more current)
    if attack.healing and attack.healing.recommendations:
        phrases = _get_fix_phrases(attack.healing.recommendations)
        if phrases:
            grid.add_row("", f"[{COLOR_COMMAND}]Suggested Fixes:[/{COLOR_COMMAND}]")
            for phrase in phrases:
                grid.add_row("", f"[{COLOR_DIM}]• {phrase}[/{COLOR_DIM}]")
            remaining = len(attack.healing.recommendations) - 3
            if remaining > 0:
                grid.add_row("", f"[{COLOR_DIM}](+{remaining} more)[/{COLOR_DIM}]")

    console.print(Padding(grid, (0, 0, 0, 4)))
    console.print()


def _render_new_finding(attack: AttackResult) -> None:
    """Render a new (non-regression) finding."""
    owasp = attack.analysis.owasp_code if attack.analysis else "LLM01"
    owasp_title = OWASP_TITLES.get(owasp, "Unknown Vulnerability")
    persona = attack.persona.value.capitalize() if attack.persona else "Unknown"
    severity_text = "CRITICAL" if owasp == "LLM01" else "HIGH"
    severity_style = f"bold {COLOR_ERROR}" if owasp == "LLM01" else COLOR_ERROR

    console.print(
        f"    [{COLOR_COMMAND}]{owasp_title}[/{COLOR_COMMAND}] [{COLOR_DIM}]{owasp}[/{COLOR_DIM}] · "
        f"[{COLOR_COMMAND}]{persona}[/{COLOR_COMMAND}] · [{severity_style}]{severity_text}[/{severity_style}]"
    )

    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=25)
    grid.add_column()

    if attack.analysis and attack.analysis.root_cause:
        root = attack.analysis.root_cause
        if "." in root:
            root = root.split(".")[0] + "."
        grid.add_row("", f"[{COLOR_DIM}]{root}[/{COLOR_DIM}]")

    if attack.healing and attack.healing.recommendations:
        phrases = _get_fix_phrases(attack.healing.recommendations)
        if phrases:
            grid.add_row("", f"[{COLOR_COMMAND}]Suggested Fixes:[/{COLOR_COMMAND}]")
            for phrase in phrases:
                grid.add_row("", f"[{COLOR_DIM}]• {phrase}[/{COLOR_DIM}]")
            remaining = len(attack.healing.recommendations) - 3
            if remaining > 0:
                grid.add_row("", f"[{COLOR_DIM}](+{remaining} more)[/{COLOR_DIM}]")

    console.print(Padding(grid, (0, 0, 0, 4)))
    console.print()


def _render_regression_finding(transition: AttackTransition) -> None:
    """Render a regression-only finding (not confirmed by new attack)."""
    owasp = transition.owasp_code or "LLM01"
    owasp_title = OWASP_TITLES.get(owasp, "Unknown Vulnerability")
    persona = transition.strategy_id.capitalize()
    severity_text = "CRITICAL" if owasp == "LLM01" else "HIGH"
    severity_style = f"bold {COLOR_ERROR}" if owasp == "LLM01" else COLOR_ERROR

    console.print(
        f"    [{COLOR_COMMAND}]{owasp_title}[/{COLOR_COMMAND}] [{COLOR_DIM}]{owasp}[/{COLOR_DIM}] · "
        f"[{COLOR_COMMAND}]{persona}[/{COLOR_COMMAND}] · [{severity_style}]{severity_text}[/{severity_style}] · "
        f"[{COLOR_ERROR}]REGRESSION[/{COLOR_ERROR}]"
    )

    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=25)
    grid.add_column()

    # Show lifecycle date
    date_text = _format_exploited_since(transition.exploited_since)
    if date_text:
        grid.add_row("", f"[{COLOR_DIM}]{date_text}[/{COLOR_DIM}]")
    else:
        grid.add_row(
            "",
            f"[{COLOR_DIM}]Known vulnerability from previous test run.[/{COLOR_DIM}]",
        )

    console.print(Padding(grid, (0, 0, 0, 4)))
    console.print()


# =============================================================================
# Error Renderers
# =============================================================================


def render_api_key_missing() -> None:
    """Render API key configuration error."""
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] API key not configured")
    console.print()
    console.print("  Serix requires an LLM provider to run attacks.")
    console.print()
    console.print("  Set one of:")
    console.print("    export OPENAI_API_KEY=sk-...")
    console.print("    export ANTHROPIC_API_KEY=sk-ant-...")
    console.print()
    console.print("  Or configure in serix.toml:")
    console.print("    [models]")
    console.print('    attacker = "gpt-4o-mini"')
    console.print()


def render_auth_error(provider: str | None) -> None:
    """Render authentication error with fix instructions."""
    from serix_v2.core.constants import PROVIDER_CONSOLE_URLS, PROVIDER_ENV_VARS

    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] Authentication failed")
    console.print()

    if provider and provider in PROVIDER_CONSOLE_URLS:
        console.print(f"  Your {provider} API key is invalid or expired.")
        console.print()
        console.print(f"  Get a new key at: {PROVIDER_CONSOLE_URLS[provider]}")
    else:
        console.print("  Your API key is invalid or expired.")

    console.print()
    console.print("  Then update your environment:")
    if provider:
        env_var = PROVIDER_ENV_VARS.get(provider, "OPENAI_API_KEY")
        console.print(f"    export {env_var}=<new-key>")
    else:
        console.print("    export OPENAI_API_KEY=<new-key>")
    console.print()


def handle_auth_error(provider: str | None, is_interactive: bool) -> bool:
    """
    Handle auth error with optional key re-entry.

    Returns True if user entered valid key and we should retry,
    False if we should exit.
    """
    import os

    from rich.prompt import Prompt

    from serix_v2.core.constants import PROVIDER_CONSOLE_URLS, PROVIDER_ENV_VARS
    from serix_v2.services.env_writer import append_to_env
    from serix_v2.services.key_validator import validate_key

    # CI mode - show full error with manual instructions and exit
    if not is_interactive:
        render_auth_error(provider)
        return False

    # Interactive mode - show streamlined error + prompt
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] Authentication failed")
    console.print()
    if provider and provider in PROVIDER_CONSOLE_URLS:
        console.print(f"  Your {provider} API key is invalid or expired.")
        console.print(f"  Get a new key at: {PROVIDER_CONSOLE_URLS[provider]}")
    else:
        console.print("  Your API key is invalid or expired.")
    console.print()

    env_var = (
        PROVIDER_ENV_VARS.get(provider, "OPENAI_API_KEY")
        if provider
        else "OPENAI_API_KEY"
    )

    try:
        new_key = Prompt.ask("  Enter new API key", password=True)

        if not new_key or not new_key.strip():
            console.print(f"  [{COLOR_DIM}]Cancelled[/{COLOR_DIM}]")
            return False

        new_key = new_key.strip()

        # Strip accidental ENV_VAR= prefix (user may paste whole line from .env)
        if new_key.startswith(f"{env_var}="):
            new_key = new_key[len(f"{env_var}=") :]

        # Validate the new key
        console.print(f"  [{COLOR_DIM}]Validating...[/{COLOR_DIM}]", end="")
        result = validate_key(provider or "openai", new_key)

        if not result.valid:
            console.print(
                f"\r  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] Key invalid: {result.error_message}"
            )
            return False

        console.print(f"\r  [{COLOR_SUCCESS}]✓[/{COLOR_SUCCESS}] Key valid    ")

        # Save to .env and update current process
        append_to_env(env_var, new_key)
        os.environ[env_var] = new_key

        console.print(f"  [{COLOR_SUCCESS}]✓[/{COLOR_SUCCESS}] Saved to .env")
        console.print()
        console.print("  Resuming test...")
        console.print()

        return True

    except KeyboardInterrupt:
        console.print()
        console.print(f"  [{COLOR_DIM}]Cancelled[/{COLOR_DIM}]")
        return False


def map_api_error(error: Exception) -> tuple[str, str, str]:
    """
    Map API exception to human-friendly (title, description, action).

    Works with all providers: OpenAI, Anthropic, Google, etc.
    litellm normalizes all provider errors to common exception types.

    Returns:
        (title, description, recommended_action)
    """
    import litellm

    # Extract provider and model from litellm exceptions
    provider = getattr(error, "llm_provider", None)
    model = getattr(error, "model", None)

    # Context string for messages
    context = f" for {model}" if model else ""
    if provider:
        context = f" ({provider}){context}"

    # Map specific error types to friendly messages
    if isinstance(error, litellm.RateLimitError):
        return (
            f"Rate Limit Exceeded{context}",
            "You've hit the API rate limit or exhausted your quota.",
            "Wait a moment and retry, or check your usage/billing",
        )
    elif isinstance(error, litellm.APIConnectionError):
        return (
            f"Connection Failed{context}",
            "Could not connect to the API server.",
            "Check your internet connection and try again",
        )
    elif isinstance(error, litellm.Timeout):
        return (
            f"Request Timed Out{context}",
            "The API request took too long to respond.",
            "Try again - the API may be experiencing high load",
        )
    elif isinstance(error, litellm.ContextWindowExceededError):
        return (
            f"Context Window Exceeded{context}",
            "The input was too long for the model's context window.",
            "Try with a smaller input or use a model with larger context",
        )
    elif isinstance(error, litellm.ContentPolicyViolationError):
        return (
            f"Content Policy Violation{context}",
            "The request was blocked by the provider's content policy.",
            "Review the input for potentially problematic content",
        )
    elif isinstance(error, litellm.BadRequestError):
        return (
            f"Bad Request{context}",
            "The API request was invalid.",
            "Check your model name and configuration",
        )
    elif isinstance(error, litellm.ServiceUnavailableError):
        return (
            f"Service Unavailable{context}",
            "The API service is temporarily unavailable.",
            "Wait a few minutes and try again",
        )
    else:
        # Generic fallback
        return (
            f"API Error{context}",
            str(error)[:200] if str(error) else "An unexpected error occurred.",
            "Check your configuration and try again",
        )


def render_api_error(error: Exception) -> None:
    """
    Render API error with friendly message and recommended action.

    Works universally across all LLM providers.
    """
    from serix_v2.core.constants import PROVIDER_USAGE_URLS

    title, description, action = map_api_error(error)

    # Extract provider for usage URL
    provider = getattr(error, "llm_provider", None)
    usage_url = PROVIDER_USAGE_URLS.get(provider) if provider else None

    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] {title}")
    console.print()
    console.print(f"  {description}")

    if usage_url:
        console.print()
        console.print(f"  Check usage at: {usage_url}")

    console.print()
    console.print(f"  [{COLOR_WARNING}]Recommended: {action}[/{COLOR_WARNING}]")
    console.print()


def render_mixed_provider_warning(
    provider: str,
    model: str,
    inferred_provider: str,
) -> None:
    """Render warning when model doesn't match selected provider."""
    panel_content = f"""
  Model '{model}' appears to be from {inferred_provider}, but provider is
  set to '{provider}'. Proceeding with mixed configuration.
"""
    console.print()
    console.print(
        Panel(panel_content, title="Mixed Provider Warning", border_style=COLOR_WARNING)
    )
    console.print()


def render_no_goal_error() -> None:
    """Render error when no goal specified."""
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] No attack goal specified")
    console.print()
    console.print("  Security testing requires at least one goal.")
    console.print()
    console.print("  Add a goal:")
    console.print('    serix test agent.py:agent --goal "reveal secrets"')
    console.print("    serix test agent.py:agent --goals-file goals.txt")
    console.print()
    console.print("  Or configure in serix.toml:")
    console.print("    [attack]")
    console.print('    goal = "Make the agent reveal sensitive information"')
    console.print()


def render_target_unreachable(target_id: str, locator: str, reason: str) -> None:
    """Render target unreachable error with context.

    Called when preflight check fails - the target couldn't respond
    to a simple test message.

    Args:
        target_id: The target's unique identifier.
        locator: The target path (e.g., "agent.py:my_agent").
        reason: The error message explaining why the target failed.
    """
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] Target Unreachable")
    console.print()
    console.print(f"  [bold]Target:[/bold]  {locator}")
    console.print(f"  [bold]ID:[/bold]      {target_id}")
    console.print(f"  [bold]Reason:[/bold]  {reason}")
    console.print()
    console.print(
        f"  [{COLOR_WARNING}]Check that your target function works correctly.[/{COLOR_WARNING}]"
    )
    console.print("  The target must return a string response when called.")
    console.print()


def render_file_not_found(path: str, cwd: str) -> None:
    """Render file not found error."""
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] Target not found")
    console.print()
    console.print(f"  File {path} does not exist.")
    console.print(f"  Working directory: {cwd}")
    console.print()


def render_function_not_found(
    file_path: str, func_name: str, available: list[str]
) -> None:
    """Render function not found error."""
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] Function not found")
    console.print()
    console.print(f"  File {file_path} exists, but {func_name} was not found.")
    console.print()
    if available:
        console.print("  Available functions:")
        for fn in available[:5]:
            console.print(f"    · {fn}")
    console.print()


def render_invalid_target_format(received: str) -> None:
    """Render invalid target format error."""
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗[/{COLOR_ERROR}] Invalid target format")
    console.print()
    console.print(f"  Received: {received}")
    console.print("  Expected: path/to/file.py:function_name")
    console.print()
    console.print("  Examples:")
    console.print('    serix test agent.py:my_agent --goal "..."')
    console.print('    serix test src/bot.py:ChatBot --goal "..."')
    console.print('    serix test http://localhost:8000/chat --goal "..."')
    console.print()


# =============================================================================
# Progress Indicators
# =============================================================================


def render_regression_phase(total: int) -> None:
    """Render regression check phase header."""
    console.print()
    console.print(
        f"  Phase 1 · Regression Check                          {total} stored attacks"
    )
    console.print()
    console.print("  Replaying attack library...")
    console.print()


def render_regression_result(
    replayed: int,
    still_exploited: int,
    now_defended: int,
) -> None:
    """Render regression check results.

    Structure matches Attacks/Vulnerabilities sections:
    - Section header at 2-space indent
    - Content at 4-space indent (nested)
    """
    console.print()
    console.print("  [bold white]Regression[/bold white]")
    console.print()
    console.print(
        f"    {replayed} [{COLOR_COMMAND}]stored attacks replayed[/{COLOR_COMMAND}]"
    )
    console.print(
        f"    {now_defended} [{COLOR_COMMAND}]now defended[/{COLOR_COMMAND}] [{COLOR_SUCCESS}]✓[/{COLOR_SUCCESS}]    {still_exploited} [{COLOR_COMMAND}]still exploited[/{COLOR_COMMAND}] [{COLOR_ERROR}]✗[/{COLOR_ERROR}]"
    )
    console.print()


# =============================================================================
# Live Progress Display (for real-time attack feedback)
# =============================================================================


class LiveProgressDisplay:
    """
    Manages Rich Live display during campaign execution.

    Renders real-time progress for:
    - Regression phase (replaying stored attacks)
    - Attack phase (per-persona, per-turn progress)
    - Reasoning feed (AI "thinking" display)

    Uses transient=True so the live display clears when stopped,
    allowing clean final render_campaign_result output.
    """

    def __init__(self, personas: list[str], depth: int) -> None:
        """
        Initialize the live progress display.

        Args:
            personas: List of persona names to display (e.g., ["jailbreaker", "extractor"])
            depth: Maximum turn depth for progress bars
        """
        self.personas = personas
        self.depth = depth
        self.phase: ProgressPhase = ProgressPhase.REGRESSION
        self.current_persona: str | None = None
        self.current_turn: int = 0
        self.completed: dict[str, tuple[bool, int]] = {}
        self.regression_current: int = 0
        self.regression_total: int = 0
        self.regression_now_defended: int = 0
        self.regression_still_exploited: int = 0
        self.reasoning: str | None = None
        self._live: Live | None = None

    def start(self) -> None:
        """Start the live display."""
        # transient=True clears display when stopped for clean final render
        self._live = Live(
            self._render(),
            console=console,
            refresh_per_second=4,
            transient=True,
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the live display."""
        if self._live:
            self._live.stop()
            self._live = None

    def update(self, event: ProgressEvent) -> None:
        """Update display state from a progress event."""
        self.phase = event.phase
        self.reasoning = event.reasoning

        if event.phase == ProgressPhase.REGRESSION:
            self.regression_current = event.regression_current
            self.regression_total = event.regression_total
            self.regression_now_defended = event.regression_now_defended
            self.regression_still_exploited = event.regression_still_exploited
        elif event.phase == ProgressPhase.ATTACKS:
            self.current_persona = event.persona
            self.current_turn = event.turn
            if event.completed_personas:
                self.completed = event.completed_personas

        if self._live:
            self._live.update(self._render())

    def _render(self) -> Group:
        """Render current progress state."""
        elements: list[Table | Text | Group] = []

        # Regression section (if applicable)
        if self.regression_total > 0:
            elements.append(self._render_regression())
            elements.append(Text(""))  # Blank line

        # Attacks section (only show after regression is complete, or if no regression)
        # Guard: only render when current_persona is set to prevent flash during transition
        if (
            self.regression_total == 0
            or self.regression_current >= self.regression_total
        ) and self.current_persona is not None:
            elements.append(self._render_attacks())

        # Reasoning feed with spinner (bottom) - italic for "thought process" feel
        if self.reasoning:
            elements.append(Text(""))  # Blank line
            spinner = Spinner("dots", style=COLOR_GRADE)
            # Use table with columns to keep spinner and text on same line
            reasoning_row = Table.grid(padding=(0, 0))
            reasoning_row.add_column(width=2)  # Indent
            reasoning_row.add_column(width=3)  # Spinner
            reasoning_row.add_column()  # Text
            reasoning_row.add_row(
                "",
                spinner,
                Text(f" {self.reasoning}", style=f"{COLOR_DIM} italic"),
            )
            elements.append(reasoning_row)

        return Group(*elements)

    def _render_regression(self) -> Group:
        """Render regression progress matching final format."""
        elements: list[Text | Table] = []

        # Section header (matches render_regression_result)
        elements.append(Text("  Regression", style="bold white"))
        elements.append(Text(""))  # Blank line

        if self.regression_current < self.regression_total:
            # In progress - just show count (spinner is at bottom with reasoning)
            elements.append(
                Text(
                    f"    {self.regression_current}/{self.regression_total} ",
                    style="default",
                )
                + Text("stored attacks replayed", style=COLOR_COMMAND)
            )
        else:
            # Completed - match render_regression_result format with full summary
            elements.append(
                Text(f"    {self.regression_total} ", style="default")
                + Text("stored attacks replayed", style=COLOR_COMMAND)
            )
            # Add "now defended ✓" and "still exploited ✗" line
            summary = Text("    ")
            summary.append(f"{self.regression_now_defended} ", style="default")
            summary.append("now defended", style=COLOR_COMMAND)
            summary.append(" ")
            summary.append("✓", style=COLOR_SUCCESS)
            summary.append("    ")
            summary.append(f"{self.regression_still_exploited} ", style="default")
            summary.append("still exploited", style=COLOR_COMMAND)
            summary.append(" ")
            summary.append("✗", style=COLOR_ERROR)
            elements.append(summary)

        return Group(*elements)

    def _render_attacks(self) -> Table:
        """Render attack progress with Table.grid() for alignment."""
        table = Table.grid(padding=(0, 2))
        table.add_column(width=49)  # Persona (25) + bar (20) + gutter (4)
        table.add_column()  # Status column

        # Section header
        table.add_row("  [bold white]New Attacks[/bold white]", "")
        table.add_row("", "")  # Blank line

        for persona in self.personas:
            persona_cap = persona.capitalize()

            if persona in self.completed:
                # Completed attack
                success, turns = self.completed[persona]
                status = "EXPLOITED" if success else "DEFENDED"
                color = COLOR_ERROR if success else COLOR_SUCCESS
                bar = self._make_completed_bar(turns, success)
                table.add_row(
                    f"    [{COLOR_COMMAND}]{persona_cap:<25}[/{COLOR_COMMAND}] {bar}",
                    f"[{color}]{status:<9}[/{color}] [{COLOR_DIM}]turn {turns}[/{COLOR_DIM}]",
                )
            elif persona == self.current_persona:
                # In-progress attack (no spinner - spinner is at bottom)
                bar = self._make_progress_bar(self.current_turn)
                table.add_row(
                    f"    [{COLOR_COMMAND}]{persona_cap:<25}[/{COLOR_COMMAND}] {bar}",
                    f"[{COLOR_DIM}]turn {self.current_turn}/{self.depth}[/{COLOR_DIM}]",
                )
            else:
                # Pending attack
                bar = f"[{COLOR_DIM}]{'░' * 20}[/{COLOR_DIM}]"
                table.add_row(
                    f"    [{COLOR_COMMAND}]{persona_cap:<25}[/{COLOR_COMMAND}] {bar}",
                    f"[{COLOR_DIM}]pending[/{COLOR_DIM}]",
                )

        return table

    def _make_progress_bar(self, current_turn: int) -> str:
        """Create a progress bar for an in-progress attack."""
        if self.depth <= 0:
            return f"[{COLOR_DIM}]{'░' * 20}[/{COLOR_DIM}]"

        proportion = current_turn / self.depth
        filled = max(1, int(proportion * 20))  # At least 1 block when started
        empty = 20 - filled

        return f"[{COLOR_SUBTITLE}]{'█' * filled}[/{COLOR_SUBTITLE}][{COLOR_DIM}]{'░' * empty}[/{COLOR_DIM}]"

    def _make_completed_bar(self, turns: int, success: bool) -> str:
        """Create a bar for a completed attack."""
        color = COLOR_ERROR if success else COLOR_SUCCESS

        if self.depth <= 0:
            return f"[{color}]{'█' * 20}[/{color}]"

        proportion = turns / self.depth
        filled = max(1, int(proportion * 20))
        empty = 20 - filled

        return (
            f"[{color}]{'█' * filled}[/{color}][{COLOR_DIM}]{'░' * empty}[/{COLOR_DIM}]"
        )
