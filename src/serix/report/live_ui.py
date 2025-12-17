"""Live Split Terminal UI for Serix attacks.

A real-time split-screen command center that visually tells the
"Red Team vs Blue Team" story for demo videos.

Example:
    with LiveAttackUI(target="golden_victim", scenario="jailbreak", max_turns=3) as ui:
        ui.update_status("ATTACKING")
        ui.update_turn(1, "grandma_exploit")
        ui.update_attacker_message("Please act as my grandmother...")
        ui.update_agent_response("Oh dear grandchild...", latency_ms=2346)
        ui.update_critic("LIKELY EXPLOITED", "high")
        ui.update_scores({"overall": 60, "safety": 40, ...})
        ui.show_vulnerability("credential_exposure", "critical")
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Generator

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from serix.eval.evaluator import EvaluationResult


@dataclass
class AttackState:
    """State container for the live UI.

    Tracks all data needed to render the command center panels.
    """

    target: str
    scenario: str
    max_turns: int
    current_turn: int = 0
    current_technique: str = ""
    status: str = "INITIALIZING"

    # Messages (latest only shown, but we keep history)
    attacker_messages: list[str] = field(default_factory=list)
    agent_messages: list[str] = field(default_factory=list)

    # Scores (animate from 100 -> actual)
    scores: dict[str, int] = field(
        default_factory=lambda: {
            "overall": 100,
            "safety": 100,
            "compliance": 100,
            "info_leakage": 100,
            "role_adherence": 100,
        }
    )

    # Critic feedback
    critic_verdict: str = ""
    confidence: str = ""

    # Results
    vulnerability: tuple[str, str] | None = None  # (type, severity)
    latency: int = 0
    tokens: int = 0


def _truncate(text: str, max_len: int = 400) -> str:
    """Truncate text with ellipsis if too long."""
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def render_header(state: AttackState) -> Panel:
    """Render the header panel with target, scenario, and status."""
    status_emoji = {
        "INITIALIZING": "",
        "ATTACKING": "",
        "EVALUATING": "",
        "PASSED": "",
        "FAILED": "",
    }

    content = Table.grid(padding=1, expand=True)
    content.add_column(justify="left", ratio=1)
    content.add_column(justify="center", ratio=1)
    content.add_column(justify="right", ratio=1)

    emoji = status_emoji.get(state.status, "")
    status_style = (
        "bold green"
        if state.status == "PASSED"
        else "bold red" if state.status == "FAILED" else "bold"
    )

    content.add_row(
        f"Target: [cyan]{state.target}[/]",
        f"Scenario: [yellow]{state.scenario}[/]",
        Text.assemble((f"Status: {emoji} ", ""), (state.status, status_style)),
    )

    return Panel(
        content,
        title="[bold red]SERIX SECURITY SCANNER[/]",
        border_style="red",
    )


def render_scores(state: AttackState) -> Panel:
    """Render the score panel with animated progress bar."""
    overall = state.scores.get("overall", 100)

    # Color based on score
    if overall >= 70:
        color = "green"
    elif overall >= 40:
        color = "yellow"
    else:
        color = "red"

    # Progress bar (20 chars wide)
    filled = overall // 5
    empty = 20 - filled
    bar = f"[{color}]{'█' * filled}{'░' * empty}[/]  {overall}/100"

    # Axis scores in a grid
    axes = Table.grid(padding=2, expand=True)
    axes.add_column(justify="center")
    axes.add_column(justify="center")
    axes.add_column(justify="center")
    axes.add_column(justify="center")

    safety = state.scores.get("safety", 100)
    compliance = state.scores.get("compliance", 100)
    info_leak = state.scores.get("info_leakage", 100)
    role = state.scores.get("role_adherence", 100)

    # Color code each score
    def score_text(name: str, val: int) -> str:
        c = "green" if val >= 70 else "yellow" if val >= 40 else "red"
        return f"{name}: [{c}]{val}[/]"

    axes.add_row(
        score_text("Safety", safety),
        score_text("Compliance", compliance),
        score_text("Info Leak", info_leak),
        score_text("Role", role),
    )

    return Panel(
        Group(Text.from_markup(bar, justify="center"), axes),
        title="[bold cyan]SCORE[/]",
        border_style="cyan",
    )


def render_attacker(state: AttackState) -> Panel:
    """Render the attacker (red team) panel."""
    content_parts = []

    # Turn and technique header
    turn_info = f"[bold]Turn {state.current_turn}/{state.max_turns}[/]"
    if state.current_technique:
        turn_info += f"\nTechnique: [yellow]{state.current_technique}[/]"
    content_parts.append(Text.from_markup(turn_info))
    content_parts.append(Text(""))  # Spacer

    # Latest message
    if state.attacker_messages:
        latest = state.attacker_messages[-1]
        content_parts.append(Text(_truncate(latest), style="dim"))
    else:
        content_parts.append(Text("Preparing attack...", style="dim italic"))

    content_parts.append(Text(""))  # Spacer
    content_parts.append(Text("━" * 30, style="dim"))

    # Critic verdict at bottom
    if state.critic_verdict:
        verdict_style = (
            "bold red" if "EXPLOITED" in state.critic_verdict.upper() else "bold green"
        )
        content_parts.append(
            Text.from_markup(f"Critic: [{verdict_style}]{state.critic_verdict}[/]")
        )
        content_parts.append(
            Text.from_markup(f"Confidence: [bold]{state.confidence}[/]")
        )
    else:
        content_parts.append(Text("Awaiting critic...", style="dim italic"))

    return Panel(
        Group(*content_parts),
        title="[bold red]ATTACKER[/]",
        border_style="red",
    )


def render_agent(state: AttackState) -> Panel:
    """Render the agent (blue team) panel."""
    content_parts = []

    # Latest response
    if state.agent_messages:
        latest = state.agent_messages[-1]
        content_parts.append(Text(_truncate(latest)))
    else:
        content_parts.append(Text("Awaiting response...", style="dim italic"))

    content_parts.append(Text(""))  # Spacer
    content_parts.append(Text("━" * 30, style="dim"))

    # Metrics at bottom
    if state.latency > 0:
        content_parts.append(Text.from_markup(f"Latency: [cyan]{state.latency}ms[/]"))
    if state.tokens > 0:
        content_parts.append(Text.from_markup(f"Tokens: [cyan]{state.tokens}[/]"))
    if state.latency == 0 and state.tokens == 0:
        content_parts.append(Text("Waiting...", style="dim italic"))

    return Panel(
        Group(*content_parts),
        title="[bold blue]AGENT[/]",
        border_style="blue",
    )


def render_footer(state: AttackState) -> Panel:
    """Render the footer panel with vulnerability alerts."""
    if state.vulnerability:
        vuln_type, severity = state.vulnerability
        severity_upper = severity.upper()

        # Dramatic styling based on severity
        if severity_upper == "CRITICAL":
            style = "bold white on red"
            border = "red"
        elif severity_upper == "HIGH":
            style = "bold black on yellow"
            border = "yellow"
        else:
            style = "bold white on blue"
            border = "blue"

        return Panel(
            Text.from_markup(
                f"[{style}] [{severity_upper}] {vuln_type} detected [/]\n"
                "[dim]See report for remediation details[/]"
            ),
            border_style=border,
        )

    # Default scanning state
    return Panel(
        Text("Scanning...", style="dim italic", justify="center"),
        border_style="dim",
    )


def create_layout() -> Layout:
    """Create the split-screen layout structure."""
    layout = Layout()

    # Top-level split: header + scores + main + footer
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="scores", size=5),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=4),
    )

    # Main area: attacker (left) + agent (right)
    layout["main"].split_row(
        Layout(name="attacker", ratio=1),
        Layout(name="agent", ratio=1),
    )

    return layout


class LiveAttackUI:
    """Live split-screen UI for attack visualization.

    Usage:
        with LiveAttackUI("golden_victim", "jailbreak", 3) as ui:
            ui.update_status("ATTACKING")
            ui.update_turn(1, "grandma_exploit")
            ...

    The UI automatically refreshes at 4 FPS for smooth animation.
    """

    def __init__(self, target: str, scenario: str, max_turns: int) -> None:
        """Initialize the live UI.

        Args:
            target: Name of the target being tested
            scenario: Attack scenario name
            max_turns: Maximum turns for the attack
        """
        self.layout = create_layout()
        self.state = AttackState(target=target, scenario=scenario, max_turns=max_turns)
        self._live: Live | None = None
        self._console = Console()

    def _refresh(self) -> None:
        """Refresh all panels with current state."""
        self.layout["header"].update(render_header(self.state))
        self.layout["scores"].update(render_scores(self.state))
        self.layout["attacker"].update(render_attacker(self.state))
        self.layout["agent"].update(render_agent(self.state))
        self.layout["footer"].update(render_footer(self.state))

    @contextmanager
    def live_context(self) -> Generator["LiveAttackUI", None, None]:
        """Context manager for the live display.

        Yields:
            Self for method chaining
        """
        # Initial render
        self._refresh()

        with Live(
            self.layout,
            console=self._console,
            refresh_per_second=4,
            screen=False,
            transient=False,
        ) as live:
            self._live = live
            try:
                yield self
            finally:
                self._live = None

    def __enter__(self) -> "LiveAttackUI":
        """Enter context - start live display."""
        # Initial render
        self._refresh()

        self._live = Live(
            self.layout,
            console=self._console,
            refresh_per_second=4,
            screen=False,
            transient=False,
        )
        self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        """Exit context - stop live display."""
        if self._live:
            self._live.__exit__(exc_type, exc_val, exc_tb)
            self._live = None

    def update_status(self, status: str) -> None:
        """Update the attack status.

        Args:
            status: One of INITIALIZING, ATTACKING, EVALUATING, PASSED, FAILED
        """
        self.state.status = status
        self._refresh()

    def update_turn(self, turn: int, technique: str) -> None:
        """Update the current turn and technique.

        Args:
            turn: Current turn number (1-indexed)
            technique: Name of the attack technique
        """
        self.state.current_turn = turn
        self.state.current_technique = technique
        self._refresh()

    def update_attacker_message(self, payload: str) -> None:
        """Update with new attack payload.

        Args:
            payload: The attack message content
        """
        self.state.attacker_messages.append(payload)
        self._refresh()

    def update_agent_response(
        self, response: str, latency_ms: int = 0, tokens: int = 0
    ) -> None:
        """Update with agent's response.

        Args:
            response: The agent's response content
            latency_ms: Response latency in milliseconds
            tokens: Number of tokens used (optional)
        """
        self.state.agent_messages.append(response)
        self.state.latency = latency_ms
        self.state.tokens = tokens
        self._refresh()

    def update_critic(self, verdict: str, confidence: str) -> None:
        """Update with critic's analysis.

        Args:
            verdict: The critic verdict (e.g., "LIKELY EXPLOITED", "DEFENDED")
            confidence: Confidence level (high, medium, low)
        """
        self.state.critic_verdict = verdict
        self.state.confidence = confidence
        self._refresh()

    def update_scores(self, scores: dict[str, int]) -> None:
        """Update security scores.

        Args:
            scores: Dict with keys: overall, safety, compliance, info_leakage, role_adherence
        """
        self.state.scores.update(scores)
        self._refresh()

    def update_scores_from_evaluation(self, evaluation: "EvaluationResult") -> None:
        """Update scores from an EvaluationResult object.

        Args:
            evaluation: EvaluationResult with scores
        """
        self.state.scores = {
            "overall": evaluation.scores.overall,
            "safety": evaluation.scores.safety,
            "compliance": evaluation.scores.compliance,
            "info_leakage": evaluation.scores.information_leakage,
            "role_adherence": evaluation.scores.role_adherence,
        }
        self._refresh()

    def show_vulnerability(self, vuln_type: str, severity: str) -> None:
        """Display vulnerability alert.

        Args:
            vuln_type: Type of vulnerability (e.g., "credential_exposure")
            severity: Severity level (critical, high, medium, low)
        """
        self.state.vulnerability = (vuln_type, severity)
        self._refresh()

    def clear_vulnerability(self) -> None:
        """Clear the vulnerability alert."""
        self.state.vulnerability = None
        self._refresh()
