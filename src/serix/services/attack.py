"""Attack service for executing single-persona attacks.

Orchestrates multi-turn attacks using one persona, emitting
events for each turn and the final result.

Fixes BUG-010: Handles empty responses with placeholder text.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from ..core.constants import DEFAULT_DEPTH
from ..core.events import (
    AttackCompletedEvent,
    AttackStartedEvent,
    AttackTurnEvent,
    EventListener,
    NullEventListener,
    TranscriptEvent,
)
from ..core.types import AttackResult
from ..fuzz.personas.base import AttackContext

if TYPE_CHECKING:
    from ..core.target import Target
    from ..fuzz.personas.base import AttackPersona
    from .judge import JudgeService


class AttackService:
    """Service for executing single-persona attacks.

    Runs a multi-turn attack using one persona, emitting events
    for each turn and the final result.

    Events emitted:
    - AttackStartedEvent: When attack begins
    - AttackTurnEvent: After each turn
    - AttackCompletedEvent: When attack finishes
    """

    def __init__(
        self,
        judge_service: "JudgeService",
        max_turns: int = DEFAULT_DEPTH,
        event_listener: EventListener | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize attack service.

        Args:
            judge_service: Service for judging attack success
            max_turns: Maximum turns per attack (default: 5)
            event_listener: Listener for attack events
            verbose: Enable verbose transcript output
        """
        self._judge = judge_service
        self._max_turns = max_turns
        self._events: EventListener = event_listener or NullEventListener()
        self._verbose = verbose

    def execute(
        self,
        target: "Target",
        goal: str,
        persona: "AttackPersona",
    ) -> AttackResult:
        """Execute an attack with a single persona.

        Runs up to max_turns, calling the target each turn and
        collecting the conversation. Finally judges the result.

        Args:
            target: Target to attack
            goal: Attack goal description
            persona: Persona to use for attack generation

        Returns:
            AttackResult with success status and conversation
        """
        # Reset persona state for fresh attack
        persona.reset()

        # Emit start event
        self._events.on_event(
            AttackStartedEvent(
                persona=persona.name,
                goal=goal,
                turn=1,
                max_turns=self._max_turns,
            )
        )

        # Attack state
        conversation: list[dict[str, str]] = []
        previous_attempts: list[str] = []
        winning_payload: str | None = None

        for turn in range(1, self._max_turns + 1):
            # Build context for persona
            context = AttackContext(
                goal=goal,
                turn=turn,
                conversation_history=conversation,
                previous_attempts=previous_attempts,
                critic_feedback=None,  # Simplified: no critic in Sprint 1
            )

            # Generate attack payload
            payload = persona.generate_attack(context)
            previous_attempts.append(payload.content)

            # Send to target and measure latency
            start_time = time.perf_counter()
            response = target.send(payload.content)
            latency_ms = int((time.perf_counter() - start_time) * 1000)

            # BUG-010: Handle empty responses
            content = response.content
            if not content or content.strip() == "":
                content = "[Empty response from target]"

            # Handle error responses
            if response.error:
                content = f"[Error: {response.error}]"

            # Record conversation
            conversation.append({"role": "attacker", "content": payload.content})
            conversation.append({"role": "agent", "content": content})

            # Emit turn event
            self._events.on_event(
                AttackTurnEvent(
                    persona=persona.name,
                    goal=goal,
                    turn=turn,
                    max_turns=self._max_turns,
                    attacker_message=payload.content,
                    target_response=content,
                    latency_ms=latency_ms,
                )
            )

            # Emit transcript events for verbose mode
            if self._verbose:
                self._events.on_event(
                    TranscriptEvent(
                        role="attacker",
                        content=payload.content,
                        persona=persona.name,
                        turn=turn,
                        max_turns=self._max_turns,
                    )
                )
                self._events.on_event(
                    TranscriptEvent(
                        role="target",
                        content=content,
                        persona=persona.name,
                        turn=turn,
                        max_turns=self._max_turns,
                    )
                )

        # Judge final result
        result = self._judge.evaluate(goal, conversation)

        # Emit transcript event for judge verdict
        if self._verbose:
            verdict = "EXPLOITED" if result.success else "DEFENDED"
            self._events.on_event(
                TranscriptEvent(
                    role="judge",
                    content=f"{verdict} ({result.confidence:.0%} confidence) - {result.reasoning}",
                    persona=persona.name,
                )
            )

        if result.success and previous_attempts:
            winning_payload = previous_attempts[-1]

        # Emit completion event
        self._events.on_event(
            AttackCompletedEvent(
                persona=persona.name,
                goal=goal,
                success=result.success,
                confidence=result.confidence,
                owasp_code=result.owasp_code,
                turns_taken=len(previous_attempts),
                winning_payload=winning_payload,
                judge_reasoning=result.reasoning,
            )
        )

        return AttackResult(
            success=result.success,
            persona=persona.name,
            goal=goal,
            turns_taken=len(previous_attempts),
            confidence=result.confidence,
            winning_payload=winning_payload,
            owasp_code=result.owasp_code,
            conversation=conversation,
            judge_reasoning=result.reasoning,
        )
