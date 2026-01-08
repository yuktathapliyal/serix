"""
Serix v2 - Regression Service

Replays stored attacks to check if vulnerabilities are fixed.
Law 3: Depends on Judge and Target protocols, not concrete classes.

Reference: Phase 5 Plan
"""

import logging

from serix_v2.core.contracts import (
    _utc_now,  # Law 1 consistency - use shared timestamp helper
)
from serix_v2.core.contracts import (
    AttackLibrary,
    AttackStatus,
    AttackTransition,
    ProgressCallback,
    ProgressEvent,
    ProgressPhase,
    RegressionResult,
    StoredAttack,
)
from serix_v2.core.protocols import Judge, Target

logger = logging.getLogger(__name__)


class RegressionService:
    """
    Replays stored attacks to check if vulnerabilities are fixed.

    Law 3 Compliant: Depends on Judge and Target protocols.
    This enables testing with MockJudge and MockTarget.

    The key value is the DELTA model:
    - "Last run: Exploited. This run: Defended" = Fixed!
    - "Last run: Defended. This run: Exploited" = Regression!
    """

    def __init__(
        self,
        judge: Judge,
        target: Target,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        """
        Initialize the regression service.

        Args:
            judge: Judge protocol implementation for evaluating attack success
            target: Target protocol implementation to replay attacks against
            progress_callback: Optional callback for live progress updates
        """
        self._judge = judge
        self._target = target
        self._progress_callback = progress_callback

    def _emit(self, event: ProgressEvent) -> None:
        """Emit a progress event if callback is registered."""
        if self._progress_callback:
            self._progress_callback(event)

    def run(
        self, library: AttackLibrary, skip_mitigated: bool = False
    ) -> RegressionResult:
        """
        Replay stored attacks and return regression results.

        # TODO: Implement parallel replay for large libraries
        # Currently sequential - may be slow for 500+ attacks.
        # Architecture supports parallelism (stateless service).

        Args:
            library: The attack library containing stored attacks to replay
            skip_mitigated: If True, only replay EXPLOITED attacks (skip DEFENDED)

        Returns:
            RegressionResult with counts and transitions
        """
        # Filter attacks based on skip_mitigated
        attacks = [
            a
            for a in library.attacks
            if not skip_mitigated or a.status == AttackStatus.EXPLOITED
        ]

        if not attacks:
            return RegressionResult()

        transitions: list[AttackTransition] = []
        still_exploited = 0
        now_defended = 0
        regressions = 0
        total = len(attacks)

        for idx, attack in enumerate(attacks):
            # Emit progress before replay (shows "Replaying...")
            self._emit(
                ProgressEvent(
                    phase=ProgressPhase.REGRESSION,
                    regression_current=idx,
                    regression_total=total,
                    regression_now_defended=now_defended,
                    regression_still_exploited=still_exploited,
                    reasoning=f"Replaying {attack.strategy_id} attack...",
                )
            )

            transition = self._replay_attack(attack)
            transitions.append(transition)

            # Update attack in-place (workflow persists via AttackStore.save())
            attack.status = transition.current_status
            attack.last_tested = _utc_now()  # Law 1 consistency

            # Streak reset logic (Phase 12O - vulnerability lifecycle tracking)
            if transition.is_regression:
                # DEFENDED → EXPLOITED: Bug came back, reset streak
                attack.exploited_since = _utc_now()
            elif transition.is_fixed:
                # EXPLOITED → DEFENDED: Hole closed, clear streak
                attack.exploited_since = None
            # else: status unchanged (EXPLOITED→EXPLOITED or DEFENDED→DEFENDED)
            #       keep exploited_since as-is (streak continues or stays None)

            # Count by transition type
            if transition.is_regression:
                regressions += 1
            elif transition.is_fixed:
                now_defended += 1
            elif transition.current_status == AttackStatus.EXPLOITED:
                still_exploited += 1

            # Emit progress after replay with updated counts
            self._emit(
                ProgressEvent(
                    phase=ProgressPhase.REGRESSION,
                    regression_current=idx + 1,
                    regression_total=total,
                    regression_now_defended=now_defended,
                    regression_still_exploited=still_exploited,
                )
            )

        return RegressionResult(
            replayed=len(attacks),
            still_exploited=still_exploited,
            now_defended=now_defended,
            regressions=regressions,
            transitions=transitions,
        )

    def _replay_attack(self, attack: StoredAttack) -> AttackTransition:
        """
        Replay a single attack against the target.

        Conservative Exception Handling:
        Target crash = DEFENDED (can't exploit a crashed agent)

        Phase 11: Now captures response + verdict for transcript display.

        Args:
            attack: The stored attack to replay

        Returns:
            AttackTransition with before/after status and evidence
        """
        previous_status = attack.status

        # Phase 11: Initialize evidence capture variables
        response: str | None = None
        verdict_reasoning: str | None = None
        verdict_confidence: float | None = None

        try:
            response = self._target(attack.payload)
            verdict = self._judge.evaluate(
                goal=attack.goal,
                payload=attack.payload,
                response=response,
            )
            current_status = verdict.verdict
            # Phase 11: Capture verdict details for report
            verdict_reasoning = verdict.reasoning
            verdict_confidence = verdict.confidence
        except Exception as e:
            # Conservative: crashed target = defended (can't exploit a crashed agent)
            logger.warning(f"Target crashed during replay of attack {attack.id}: {e}")
            current_status = AttackStatus.DEFENDED
            response = f"[Target crashed during replay: {type(e).__name__}]"
            verdict_reasoning = f"Target threw {type(e).__name__} during replay"
            verdict_confidence = 1.0  # Certain it's defended

        return AttackTransition(
            attack_id=attack.id,
            goal=attack.goal,
            strategy_id=attack.strategy_id,
            payload=attack.payload,
            previous_status=previous_status,
            current_status=current_status,
            # Phase 11: Include evidence
            response=response,
            verdict_reasoning=verdict_reasoning,
            verdict_confidence=verdict_confidence,
            # Phase 12O: Copy for findings display
            owasp_code=attack.owasp_code,
            exploited_since=attack.exploited_since,
        )
