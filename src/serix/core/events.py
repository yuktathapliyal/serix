"""Events emitted by business logic for renderers to consume."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


class EventListener(Protocol):
    """Protocol for anything that receives events."""

    def on_event(self, event: object) -> None:
        """Handle an event."""
        ...


@dataclass
class NullEventListener:
    """Event listener that discards all events. Useful for testing."""

    def on_event(self, event: object) -> None:
        pass


# ============================================================
# ATTACK EVENTS
# ============================================================
@dataclass
class AttackStartedEvent:
    """Emitted when an attack begins."""

    persona: str
    goal: str
    turn: int
    max_turns: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AttackTurnEvent:
    """Emitted after each attack turn."""

    persona: str
    goal: str
    turn: int
    max_turns: int
    attacker_message: str
    target_response: str
    latency_ms: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AttackCompletedEvent:
    """Emitted when an attack finishes."""

    persona: str
    goal: str
    success: bool
    confidence: float
    owasp_code: str | None
    turns_taken: int
    winning_payload: str | None = None
    judge_reasoning: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


# ============================================================
# REGRESSION EVENTS
# ============================================================
@dataclass
class RegressionStartedEvent:
    """Emitted when regression check begins."""

    total_attacks: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class RegressionAttackEvent:
    """Emitted for each regression attack replayed."""

    attack_id: str
    goal: str
    strategy_id: str
    previous_status: str
    current_result: str
    changed: bool
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class RegressionCompletedEvent:
    """Emitted when regression check finishes."""

    total_replayed: int
    still_exploited: int
    now_defended: int
    timestamp: datetime = field(default_factory=datetime.now)


# ============================================================
# HEALING EVENTS
# ============================================================
@dataclass
class HealingStartedEvent:
    """Emitted when healing generation begins."""

    successful_attacks: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class HealingGeneratedEvent:
    """Emitted when a healing patch is generated."""

    diff: str
    confidence: float
    owasp_code: str
    vulnerability_type: str
    recommendations: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


# ============================================================
# WORKFLOW EVENTS
# ============================================================
@dataclass
class WorkflowStartedEvent:
    """Emitted when a workflow begins."""

    command: str
    target: str
    goals: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class WorkflowCompletedEvent:
    """Emitted when a workflow finishes."""

    command: str
    total_attacks: int
    exploited: int
    defended: int
    duration_seconds: float
    exit_code: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class WorkflowCancelledEvent:
    """Emitted when a workflow is cancelled."""

    command: str
    reason: str = "User interrupted"
    timestamp: datetime = field(default_factory=datetime.now)


# ============================================================
# CAPTURE/PLAYBACK EVENTS
# ============================================================
@dataclass
class CaptureEvent:
    """Emitted when an API call is captured."""

    index: int
    model: str
    latency_ms: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class PlaybackEvent:
    """Emitted when an API response is replayed."""

    index: int
    model: str
    timestamp: datetime = field(default_factory=datetime.now)


# ============================================================
# TRANSCRIPT EVENTS (--verbose mode)
# ============================================================
@dataclass
class TranscriptEvent:
    """Emitted for verbose transcript display.

    Color coding:
    - Red: Attacker messages
    - Green: Target/Agent responses
    - Yellow: Judge verdicts
    """

    role: str  # "attacker", "target", "judge"
    content: str
    persona: str = ""
    turn: int = 0
    max_turns: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
