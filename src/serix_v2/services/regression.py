"""
Serix v2 - Regression Service

Replays stored attacks to check if vulnerabilities are fixed.
Law 3: Depends on Judge and Target protocols, not concrete classes.

Reference: Phase 5 Plan
"""

from serix_v2.core.contracts import (
    _utc_now,  # Law 1 consistency - use shared timestamp helper
)
from serix_v2.core.contracts import (
    AttackLibrary,
    AttackStatus,
    AttackTransition,
    RegressionResult,
    StoredAttack,
)
from serix_v2.core.protocols import Judge, Target


class RegressionService:
    """
    Replays stored attacks to check if vulnerabilities are fixed.

    Law 3 Compliant: Depends on Judge and Target protocols.
    This enables testing with MockJudge and MockTarget.

    The key value is the DELTA model:
    - "Last run: Exploited. This run: Defended" = Fixed!
    - "Last run: Defended. This run: Exploited" = Regression!
    """

    def __init__(self, judge: Judge, target: Target) -> None:
        """
        Initialize the regression service.

        Args:
            judge: Judge protocol implementation for evaluating attack success
            target: Target protocol implementation to replay attacks against
        """
        self._judge = judge
        self._target = target

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

        for attack in attacks:
            transition = self._replay_attack(attack)
            transitions.append(transition)

            # Update attack in-place (workflow persists via AttackStore.save())
            attack.status = transition.current_status
            attack.last_tested = _utc_now()  # Law 1 consistency

            # Count by transition type
            if transition.is_regression:
                regressions += 1
            elif transition.is_fixed:
                now_defended += 1
            elif transition.current_status == AttackStatus.EXPLOITED:
                still_exploited += 1

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

        Args:
            attack: The stored attack to replay

        Returns:
            AttackTransition with before/after status
        """
        previous_status = attack.status

        try:
            response = self._target(attack.payload)
            verdict = self._judge.evaluate(
                goal=attack.goal,
                payload=attack.payload,
                response=response,
            )
            current_status = verdict.verdict
        except Exception:
            # Conservative: crashed target = defended
            current_status = AttackStatus.DEFENDED

        return AttackTransition(
            attack_id=attack.id,
            goal=attack.goal,
            strategy_id=attack.strategy_id,
            payload=attack.payload,
            previous_status=previous_status,
            current_status=current_status,
        )
