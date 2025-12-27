"""Regression service for immune check (replaying known exploits).

The regression service replays previously successful exploits against
a target to verify if they're now defended. This is the "Immune Check"
feature that makes Serix feel smart.

Flow:
1. Load exploited attacks from storage
2. Replay each attack payload against target
3. Judge if attack still succeeds
4. Mark as "defended" if attack now fails
5. Emit events for UI rendering
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.events import (
    EventListener,
    NullEventListener,
    RegressionAttackEvent,
    RegressionCompletedEvent,
    RegressionStartedEvent,
)
from ..core.types import StoredAttack

if TYPE_CHECKING:
    from ..core.target import Target
    from .judge import JudgeService
    from .storage import StorageService


@dataclass
class RegressionResult:
    """Result of a regression check (immune check).

    Attributes:
        total_replayed: Number of attacks replayed
        still_exploited: Number still successful
        now_defended: Number now blocked (fixed!)
        attacks: List of (attack, still_exploited) tuples
    """

    total_replayed: int = 0
    still_exploited: int = 0
    now_defended: int = 0
    attacks: list[tuple[StoredAttack, bool]] = field(default_factory=list)

    @property
    def all_defended(self) -> bool:
        """Check if all replayed attacks are now defended."""
        return self.still_exploited == 0 and self.total_replayed > 0


class RegressionService:
    """Service for regression testing (immune check).

    Replays previously successful exploits to verify if the target
    has been hardened. Updates attack status if now defended.

    The "FIXED!" moment is one of the most powerful feedback loops
    for developers using Serix - it shows their hardening worked.
    """

    def __init__(
        self,
        storage: "StorageService",
        judge: "JudgeService",
        event_listener: EventListener | None = None,
    ) -> None:
        """Initialize regression service.

        Args:
            storage: Storage service for loading/saving attacks
            judge: Judge service for evaluating responses
            event_listener: Listener for regression events
        """
        self._storage = storage
        self._judge = judge
        self._events: EventListener = event_listener or NullEventListener()

    def run(
        self,
        target: "Target",
        target_id: str,
        skip_mitigated: bool = False,
    ) -> RegressionResult:
        """Run regression check on known exploits.

        Replays each exploited attack from the library against the
        target and checks if it still succeeds. Updates status to
        "defended" if the attack now fails.

        Args:
            target: Target to test
            target_id: Target identifier for storage lookup
            skip_mitigated: If True, skip attacks already marked defended

        Returns:
            RegressionResult with replay outcomes
        """
        # Load exploited attacks
        attacks = self._storage.get_exploited_attacks(target_id)

        if not attacks:
            # No known exploits to replay
            return RegressionResult()

        # Emit start event
        self._events.on_event(RegressionStartedEvent(total_attacks=len(attacks)))

        results: list[tuple[StoredAttack, bool]] = []
        still_exploited = 0
        now_defended = 0

        for attack in attacks:
            # Replay the attack payload
            try:
                response = target.send(attack.payload)
                content = response.content if response.content else "[Empty response]"
            except Exception as e:
                # Target error - treat as defended (target rejected the payload)
                content = f"[Error: {e}]"

            # Build minimal conversation for judge
            conversation = [
                {"role": "attacker", "content": attack.payload},
                {"role": "agent", "content": content},
            ]

            # Judge the response
            try:
                judge_result = self._judge.evaluate(attack.goal, conversation)
                is_exploited = judge_result.success
            except Exception:
                # Judge error - conservatively treat as still exploited
                is_exploited = True

            # Determine if status changed
            changed = not is_exploited  # Was exploited, now defended

            if is_exploited:
                still_exploited += 1
            else:
                now_defended += 1
                # Update storage - attack is now defended
                self._storage.update_attack_status(
                    target_id,
                    attack.id,
                    "defended",
                )

            results.append((attack, is_exploited))

            # Emit event for each attack
            self._events.on_event(
                RegressionAttackEvent(
                    attack_id=attack.id,
                    goal=attack.goal,
                    strategy_id=attack.strategy_id,
                    previous_status=attack.status,
                    current_result="exploited" if is_exploited else "defended",
                    changed=changed,
                )
            )

        # Emit completion event
        self._events.on_event(
            RegressionCompletedEvent(
                total_replayed=len(attacks),
                still_exploited=still_exploited,
                now_defended=now_defended,
            )
        )

        return RegressionResult(
            total_replayed=len(attacks),
            still_exploited=still_exploited,
            now_defended=now_defended,
            attacks=results,
        )

    def has_known_exploits(self, target_id: str) -> bool:
        """Check if target has any known exploits.

        Useful for deciding whether to show immune check UI.

        Args:
            target_id: Target identifier

        Returns:
            True if target has exploited attacks in library
        """
        attacks = self._storage.get_exploited_attacks(target_id)
        return len(attacks) > 0
