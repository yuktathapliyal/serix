"""
Serix v2 - Console Renderer

All Rich formatting for CLI output.

Law 2 Compliance: This is the ONLY place where Rich formatting
is allowed in serix_v2. Commands call these functions for display.

Guardrail 5: Display Isolation - All rich/tables/bars go HERE.
"""

from rich.console import Console
from rich.panel import Panel

from serix_v2.core.contracts import AttackResult, CampaignResult, Grade
from serix_v2.services.status import StatusSummary, TargetStatus

console = Console()


# =============================================================================
# Init Command Renderers
# =============================================================================


def render_init_success(path: str, version: str) -> None:
    """Render successful init message."""
    console.print()
    console.print(f"  [green]✓[/green] Created {path}")
    console.print()
    console.print("  [dim]What's next?[/dim]")
    console.print("    1. Edit serix.toml to configure your target")
    console.print("    2. Run [cyan]serix test[/cyan] to start security testing")
    console.print()
    console.print("  [dim]Docs[/dim]  https://github.com/yuktathapliyal/serix")
    console.print()


def render_init_exists(path: str) -> None:
    """Render warning when config already exists."""
    console.print()
    console.print(f"  [yellow]⚠[/yellow] {path} already exists")
    console.print()
    console.print("  To overwrite, run:")
    console.print("    [cyan]serix init --force[/cyan]")
    console.print()


def render_init_replaced(path: str, backup_path: str) -> None:
    """Render message when config was replaced."""
    console.print()
    console.print(f"  [green]✓[/green] Replaced {path}")
    console.print(f"    Backup saved to {backup_path}")
    console.print()
    console.print("  [dim]What's next?[/dim]")
    console.print("    1. Edit serix.toml to configure your target")
    console.print("    2. Run [cyan]serix test[/cyan] to start security testing")
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
    console.print("  [dim]View details:[/dim] serix status --name <alias> -v")
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
        border_style="dim",
    )
    console.print()
    console.print(panel)
    console.print()
    console.print("  [dim]Get started:[/dim]")
    console.print('    serix test agent.py:my_agent --goal "reveal secrets"')
    console.print()


def render_target_not_found(
    name: str | None = None, target_id: str | None = None
) -> None:
    """Render error when target not found."""
    identifier = name or target_id
    console.print()
    console.print("  [red]✗[/red] Target not found")
    console.print()
    console.print(f"  No target with {'name' if name else 'ID'}: {identifier}")
    console.print()
    console.print("  [dim]View all:[/dim] serix status")
    console.print()


def _render_target_row(target: TargetStatus, verbose: bool) -> None:
    """Render a single target row in status table."""
    # Name or target_id
    header = target.name or target.locator[:40]
    console.print(
        f"  [bold]{header}[/bold]"
        + " " * max(0, 45 - len(header))
        + f"[dim]{target.target_id}[/dim]"
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

    # Color based on percentage
    if percent >= 80:
        color = "green"
    elif percent >= 60:
        color = "yellow"
    else:
        color = "red"

    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"


def _get_grade_color(grade: str) -> str:
    """Get color for grade display."""
    if grade == "A":
        return "green"
    elif grade == "B":
        return "green"
    elif grade == "C":
        return "yellow"
    elif grade == "D":
        return "yellow"
    else:
        return "red"


# =============================================================================
# Test Command Renderers
# =============================================================================


def render_campaign_header(
    target_path: str,
    target_id: str,
    goals: list[str],
    mode: str,
    depth: int,
) -> None:
    """Render campaign header with target info."""
    console.print()
    console.print(
        "  [bold]S E R I X[/bold]                                    [dim]Agent Security Testing[/dim]"
    )
    console.print()
    console.print(f"  Target     {target_path}")
    console.print(f"  ID         {target_id}")

    if len(goals) == 1:
        console.print(f"  Goal       {goals[0]}")
    else:
        console.print(f"  Goals      {len(goals)} objectives")
        for goal in goals[:3]:  # Show first 3
            console.print(
                f"             · {goal[:50]}{'...' if len(goal) > 50 else ''}"
            )
        if len(goals) > 3:
            console.print(f"             · ... and {len(goals) - 3} more")

    console.print(f"  Mode       {mode} · depth {depth}")
    console.print()


def render_campaign_result(result: CampaignResult, verbose: bool = False) -> None:
    """Render complete campaign result."""
    # Header
    render_campaign_header(
        target_path=result.target_locator,
        target_id=result.target_id,
        goals=[],  # Already shown in header before run
        mode="adaptive" if result.attacks else "unknown",
        depth=5,
    )

    # Attack results by persona
    _render_attack_results(result.attacks, verbose)

    # Grade panel
    render_grade_panel(result.score.grade, result.score.overall_score, result.attacks)

    # Vulnerabilities (if any exploits)
    exploits = [a for a in result.attacks if a.success]
    if exploits:
        render_vulnerabilities(exploits)

    # Footer
    console.print()
    console.print(f"  Duration   {result.duration_seconds:.1f}s")

    if not result.passed:
        console.print("  Report     ./serix-report.html")

    console.print()


def _render_attack_results(attacks: list[AttackResult], verbose: bool) -> None:
    """Render attack results with health bars."""
    console.print()

    for attack in attacks:
        status_text = (
            "[red]EXPLOITED[/red]" if attack.success else "[green]DEFENDED[/green]"
        )
        turns_text = (
            f"turn {len(attack.turns)}"
            if attack.success
            else f"{len(attack.turns)} turns"
        )

        # Progress bar
        if attack.success:
            # Fill to the turn where exploit happened
            filled = len(attack.turns) * 4
            bar = f"[red]{'█' * filled}[/red][dim]{'░' * (20 - filled)}[/dim]"
        else:
            bar = f"[green]{'█' * 20}[/green]"

        persona_name = (
            attack.persona.value.capitalize() if attack.persona else "Unknown"
        )
        console.print(f"  {persona_name:<14} {bar} {status_text:<20} {turns_text}")

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


def render_grade_panel(grade: Grade, score: int, attacks: list[AttackResult]) -> None:
    """Render the security grade panel."""
    exploits = sum(1 for a in attacks if a.success)

    if exploits == 0:
        verdict = "All attacks defended"
    else:
        verdict = f"{exploits} exploit{'s' if exploits > 1 else ''} discovered"

    # Health bar
    filled = score // 5
    bar = f"{'█' * filled}{'░' * (20 - filled)}"

    # Grade color
    grade_color = _get_grade_color(grade.value)

    panel_content = f"""
                    [{grade_color}]GRADE {grade.value}[/{grade_color}]

              {verdict}

     {bar}
                     {score}%
"""

    panel = Panel(panel_content, border_style="dim")
    console.print(panel)


def render_vulnerabilities(exploits: list[AttackResult]) -> None:
    """Render vulnerability details."""
    console.print()
    console.print("  [bold]Vulnerabilities[/bold]")
    console.print()

    for attack in exploits:
        owasp = attack.analysis.owasp_code if attack.analysis else "LLM01"
        vuln_type = (
            attack.analysis.vulnerability_type
            if attack.analysis
            else "Prompt Injection"
        )
        persona = attack.persona.value.capitalize() if attack.persona else "Unknown"
        severity = "CRITICAL" if owasp == "LLM01" else "HIGH"

        console.print(
            f"  [bold]{owasp}[/bold]  {vuln_type} · {persona}"
            + " " * 20
            + f"[red]{severity}[/red]"
        )
        if attack.analysis and attack.analysis.explanation:
            console.print(f"         {attack.analysis.explanation[:60]}")
        console.print()


def render_healing_patch(diff: str) -> None:
    """Render suggested patch."""
    console.print()
    console.print(
        "  [bold]Suggested Fix[/bold]                                     [dim]Confidence 85%[/dim]"
    )
    console.print()
    for line in diff.split("\n")[:15]:
        if line.startswith("+"):
            console.print(f"  [green]{line}[/green]")
        elif line.startswith("-"):
            console.print(f"  [red]{line}[/red]")
        else:
            console.print(f"  {line}")
    console.print()


# =============================================================================
# Error Renderers
# =============================================================================


def render_api_key_missing() -> None:
    """Render API key configuration error."""
    console.print()
    console.print("  [red]✗[/red] API key not configured")
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


def render_no_goal_error() -> None:
    """Render error when no goal specified."""
    console.print()
    console.print("  [red]✗[/red] No attack goal specified")
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


def render_file_not_found(path: str, cwd: str) -> None:
    """Render file not found error."""
    console.print()
    console.print("  [red]✗[/red] Target not found")
    console.print()
    console.print(f"  File {path} does not exist.")
    console.print(f"  Working directory: {cwd}")
    console.print()


def render_function_not_found(
    file_path: str, func_name: str, available: list[str]
) -> None:
    """Render function not found error."""
    console.print()
    console.print("  [red]✗[/red] Function not found")
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
    console.print("  [red]✗[/red] Invalid target format")
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
    """Render regression check results."""
    console.print()
    console.print(
        f"  {now_defended} now defended [green]✓[/green]    {still_exploited} still exploited [red]✗[/red]"
    )
    console.print()
