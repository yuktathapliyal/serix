"""Progress renderer for CLI output with spinners.

Provides spinner-based progress tracking for parallel persona
execution. Uses Rich Progress with SpinnerColumn for concurrent
persona tracking.

Note: Full "War Room" TUI with panels deferred to Sprint 5 (LiveRenderer).
"""

from __future__ import annotations

import threading
from typing import Any

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from ...core.events import (
    AttackCompletedEvent,
    AttackStartedEvent,
    AttackTurnEvent,
    HealingGeneratedEvent,
    HealingStartedEvent,
    RegressionAttackEvent,
    RegressionCompletedEvent,
    RegressionStartedEvent,
    TranscriptEvent,
    WorkflowCancelledEvent,
    WorkflowCompletedEvent,
    WorkflowStartedEvent,
)


class StaticRenderer:
    """Renders events with spinners for parallel progress.

    Uses Rich Progress with SpinnerColumn for concurrent persona tracking.
    Implements RendererProtocol.
    """

    def __init__(self, console: Console | None = None) -> None:
        """Initialize renderer.

        Args:
            console: Rich console (default: new console)
        """
        self._console = console or Console()
        self._progress: Progress | None = None
        self._tasks: dict[str, Any] = {}  # persona -> task_id
        self._results: dict[str, bool | None] = {}  # persona -> success/None
        self._lock = threading.Lock()  # Protects progress initialization

    def on_event(self, event: object) -> None:
        """Handle an event and render appropriately.

        Implements RendererProtocol.
        """
        if isinstance(event, WorkflowStartedEvent):
            self._on_workflow_started(event)
        elif isinstance(event, RegressionStartedEvent):
            self._on_regression_started(event)
        elif isinstance(event, RegressionAttackEvent):
            self._on_regression_attack(event)
        elif isinstance(event, RegressionCompletedEvent):
            self._on_regression_completed(event)
        elif isinstance(event, AttackStartedEvent):
            self._on_attack_started(event)
        elif isinstance(event, AttackTurnEvent):
            self._on_attack_turn(event)
        elif isinstance(event, AttackCompletedEvent):
            self._on_attack_completed(event)
        elif isinstance(event, WorkflowCompletedEvent):
            self._on_workflow_completed(event)
        elif isinstance(event, WorkflowCancelledEvent):
            self._on_workflow_cancelled(event)
        elif isinstance(event, HealingStartedEvent):
            self._on_healing_started(event)
        elif isinstance(event, HealingGeneratedEvent):
            self._on_healing_generated(event)
        elif isinstance(event, TranscriptEvent):
            self._on_transcript(event)

    def _on_workflow_started(self, event: WorkflowStartedEvent) -> None:
        """Handle workflow start - initialize progress display."""
        self._console.print()
        self._console.print("[bold]Running security test...[/bold]")
        self._console.print(f"[dim]Target: {event.target}[/dim]")
        self._console.print(f"[dim]Goals: {len(event.goals)}[/dim]")

    # =========================================================================
    # Regression Event Handlers
    # =========================================================================

    def _on_regression_started(self, event: RegressionStartedEvent) -> None:
        """Handle regression start - show immune check header."""
        self._console.print()
        self._console.print("[bold cyan]Immune Check[/bold cyan]")
        self._console.print(
            f"[dim]Replaying {event.total_attacks} known exploit(s)...[/dim]"
        )

    def _on_regression_attack(self, event: RegressionAttackEvent) -> None:
        """Handle regression attack result - show status."""
        if event.current_result == "exploited":
            status = "[red]Still exploited[/red]"
        else:
            status = "[green]Now defended[/green]"

        # Highlight when an attack is now defended (the FIXED! moment)
        if event.changed:
            status += " [bold yellow](FIXED!)[/bold yellow]"

        goal_preview = event.goal[:40] + "..." if len(event.goal) > 40 else event.goal
        self._console.print(f"  {event.attack_id}: {status} - {goal_preview}")

    def _on_regression_completed(self, event: RegressionCompletedEvent) -> None:
        """Handle regression completion - show summary."""
        self._console.print()
        self._console.print("[bold]Immune Check Results:[/bold]")
        self._console.print(f"  Replayed: {event.total_replayed}")
        self._console.print(f"  Still exploited: [red]{event.still_exploited}[/red]")
        self._console.print(f"  Now defended: [green]{event.now_defended}[/green]")

        if event.now_defended > 0:
            self._console.print()
            self._console.print(
                f"[green bold]{event.now_defended} vulnerability(ies) fixed![/green bold]"
            )

    # =========================================================================
    # Attack Event Handlers
    # =========================================================================

    def _start_attack_progress(self) -> None:
        """Start the attack progress display if not already started.

        Uses a lock to prevent race conditions when multiple personas
        start simultaneously in parallel execution.
        """
        with self._lock:
            if self._progress is not None:
                return

            self._console.print()
            self._console.print("[bold]New Attack Campaign[/bold]")
            self._console.print()

            # Initialize progress with spinners
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold]{task.fields[persona]:<15}[/bold]"),
                BarColumn(bar_width=20),
                TextColumn("[dim]Turn {task.completed}/{task.total}[/dim]"),
                TextColumn("{task.fields[status]}"),
                console=self._console,
                transient=False,
            )
            self._progress.start()

    def _on_attack_started(self, event: AttackStartedEvent) -> None:
        """Handle attack start - create spinner for persona."""
        # Start progress display on first attack
        self._start_attack_progress()

        if self._progress is None:
            return

        # Create task for this persona if not exists (thread-safe)
        key = f"{event.persona}:{event.goal[:20]}"
        with self._lock:
            if key not in self._tasks:
                task_id = self._progress.add_task(
                    "",
                    total=event.max_turns,
                    persona=event.persona,
                    status="",
                )
                self._tasks[key] = task_id
                self._results[key] = None

    def _on_attack_turn(self, event: AttackTurnEvent) -> None:
        """Handle attack turn - update progress bar."""
        if self._progress is None:
            return

        key = f"{event.persona}:{event.goal[:20]}"
        if key in self._tasks:
            self._progress.update(
                self._tasks[key],
                completed=event.turn,
            )

    def _on_attack_completed(self, event: AttackCompletedEvent) -> None:
        """Handle attack completion - show result."""
        if self._progress is None:
            return

        key = f"{event.persona}:{event.goal[:20]}"
        self._results[key] = event.success

        if key in self._tasks:
            # Update status with result
            if event.success:
                status = "[red]EXPLOITED[/red]"
            else:
                status = "[green]Defended[/green]"

            self._progress.update(
                self._tasks[key],
                completed=event.turns_taken,
                status=status,
            )

    def _on_workflow_completed(self, event: WorkflowCompletedEvent) -> None:
        """Handle workflow completion - show summary."""
        if self._progress:
            self._progress.stop()

        self._console.print()
        self._console.print("[bold]Results:[/bold]")
        self._console.print(f"  Total attacks: {event.total_attacks}")
        self._console.print(f"  Exploited: [red]{event.exploited}[/red]")
        self._console.print(f"  Defended: [green]{event.defended}[/green]")
        self._console.print(f"  Duration: {event.duration_seconds:.1f}s")

        if event.exploited > 0:
            self._console.print()
            self._console.print("[red bold]VULNERABLE[/red bold]")
        else:
            self._console.print()
            self._console.print("[green bold]SECURE[/green bold]")

    def _on_workflow_cancelled(self, event: WorkflowCancelledEvent) -> None:
        """Handle workflow cancellation."""
        if self._progress:
            self._progress.stop()

        self._console.print()
        self._console.print("[yellow]Interrupted. Cleaning up...[/yellow]")

    # =========================================================================
    # Healing Event Handlers
    # =========================================================================

    def _on_healing_started(self, event: HealingStartedEvent) -> None:
        """Handle healing start - show header."""
        self._console.print()
        self._console.print("[bold cyan]Generating Healing Patch[/bold cyan]")
        self._console.print(
            f"[dim]Analyzing {event.successful_attacks} successful attack(s)...[/dim]"
        )

    def _on_healing_generated(self, event: HealingGeneratedEvent) -> None:
        """Handle healing generated - show results."""
        self._console.print()
        self._console.print("[bold green]Healing Generated[/bold green]")
        self._console.print(f"  Vulnerability: {event.vulnerability_type}")
        self._console.print(f"  OWASP: {event.owasp_code}")
        self._console.print(f"  Confidence: {int(event.confidence * 100)}%")

        if event.diff:
            self._console.print()
            self._console.print("[bold]Patch Preview:[/bold]")
            # Show first few lines of diff
            diff_lines = event.diff.split("\n")[:6]
            for line in diff_lines:
                if line.startswith("+") and not line.startswith("+++"):
                    self._console.print(f"  [green]{line}[/green]")
                elif line.startswith("-") and not line.startswith("---"):
                    self._console.print(f"  [red]{line}[/red]")
                else:
                    self._console.print(f"  [dim]{line}[/dim]")
            if len(event.diff.split("\n")) > 6:
                self._console.print("  [dim]...[/dim]")

        if event.recommendations:
            self._console.print()
            self._console.print("[bold]Recommendations:[/bold]")
            for rec in event.recommendations:
                self._console.print(f"  [yellow]![/yellow] {rec}")

    # =========================================================================
    # Transcript Event Handlers (--verbose mode)
    # =========================================================================

    def _on_transcript(self, event: TranscriptEvent) -> None:
        """Handle transcript event - display colored conversation.

        Color coding:
        - Red: Attacker messages
        - Green: Target/Agent responses
        - Yellow: Judge verdicts
        """
        # Truncate long content for readability
        content = event.content
        if len(content) > 500:
            content = content[:500] + "..."

        if event.role == "attacker":
            # Red for attacker
            header = f"[bold red]ATTACKER[/bold red] ({event.persona} turn {event.turn}/{event.max_turns})"
            self._console.print(f"  {header}")
            self._console.print(f"  [red]{content}[/red]")
        elif event.role == "target":
            # Green for target
            header = "[bold green]TARGET[/bold green]"
            self._console.print(f"  {header}")
            self._console.print(f"  [green]{content}[/green]")
        elif event.role == "judge":
            # Yellow for judge
            header = "[bold yellow]JUDGE[/bold yellow]"
            self._console.print(f"  {header}")
            self._console.print(f"  [yellow]{content}[/yellow]")
        else:
            # Fallback for unknown roles
            self._console.print(f"  [{event.role.upper()}] {content}")

        self._console.print()  # Blank line between entries
