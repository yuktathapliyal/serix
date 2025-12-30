"""
Serix v2 - Adversary Engine

P1-S1-T01: The core attack turn loop.

This module implements the AdversaryEngine which orchestrates multi-turn
attacks against a target using the Attacker, Judge, and Critic protocols.

Law Compliance:
- Law 1: Returns AttackResult (Pydantic model)
- Law 2: No typer/rich/click imports
- Law 3: Depends only on protocols (Target, Attacker, Judge, Critic)
- Law 4: No module-level globals
- Law 5: exhaustive and depth flags map to code branches
"""

import time
from typing import Optional

from serix_v2.core.contracts import (
    AttackMode,
    AttackResult,
    AttackStatus,
    AttackTurn,
    JudgeVerdict,
    Persona,
)
from serix_v2.core.protocols import Attacker, Critic, Judge, Target


class AdversaryEngine:
    """
    The core attack engine that orchestrates multi-turn attacks.

    The engine runs a loop that:
    1. Generates attack payloads via Attacker
    2. Sends payloads to Target
    3. Evaluates success via Judge
    4. Gets strategic feedback via Critic (in ADAPTIVE mode)

    Stopping conditions:
    - Judge says EXPLOITED and exhaustive=False → early exit
    - Critic says should_continue=False → stop (strategy exhausted)
    - Turn count reaches depth → stop (depth limit)

    Sticky Success Rule:
    Once Judge returns EXPLOITED on any turn, success stays True for the
    entire attack, even if subsequent turns are DEFENDED.
    """

    def __init__(
        self,
        target: Target,
        attacker: Attacker,
        judge: Judge,
        critic: Optional[Critic] = None,
    ) -> None:
        """
        Initialize the AdversaryEngine.

        Args:
            target: The target to attack (implements Target protocol)
            attacker: The attacker to generate payloads (implements Attacker protocol)
            judge: The judge to evaluate success (implements Judge protocol)
            critic: Optional critic for strategy feedback (implements Critic protocol)
                   Required for ADAPTIVE mode, ignored in STATIC mode.
        """
        self._target = target
        self._attacker = attacker
        self._judge = judge
        self._critic = critic

    def run(
        self,
        goal: str,
        depth: int = 5,
        exhaustive: bool = False,
        mode: AttackMode = AttackMode.ADAPTIVE,
        persona: Persona = Persona.JAILBREAKER,
    ) -> AttackResult:
        """
        Execute the attack loop.

        Args:
            goal: The attack goal (what we're trying to achieve)
            depth: Maximum number of turns (default: 5)
            exhaustive: If True, continue after exploit to find more; if False, stop on first exploit
            mode: ADAPTIVE (use critic) or STATIC (no critic feedback)
            persona: The attack persona being used

        Returns:
            AttackResult with all turns, success status, and winning payload if found
        """
        turns: list[AttackTurn] = []
        found_exploit = False  # Sticky success flag
        winning_payloads: list[str] = []  # FH-02: Capture all winning payloads
        final_verdict: Optional[JudgeVerdict] = None

        turn_number = 0

        while turn_number < depth:
            turn_number += 1

            # 1. Generate attack payload
            payload = self._attacker.generate(goal, turns)

            # 2. Send to target and measure latency
            # FH-01: Wrap in try/except to survive target crashes
            error_type: Optional[str] = None
            start_time = time.perf_counter()
            try:
                response = self._target(payload)
            except Exception as e:
                # Record error as data point, don't crash the engine
                error_type = type(e).__name__
                response = f"[TARGET_ERROR] {error_type}: {str(e)[:200]}"
            latency_ms = (time.perf_counter() - start_time) * 1000

            # 3. Judge evaluates if this turn was an exploit
            verdict = self._judge.evaluate(goal, payload, response)
            final_verdict = verdict  # Track last verdict for result

            # 4. Check for exploit
            if verdict.verdict == AttackStatus.EXPLOITED:
                found_exploit = True  # STICKY: stays True forever
                winning_payloads.append(payload)  # FH-02: Capture ALL winning payloads

                # Non-exhaustive mode: stop on first exploit
                if not exhaustive:
                    # Create turn with no critic feedback (we're stopping)
                    turn = AttackTurn(
                        turn_number=turn_number,
                        payload=payload,
                        response=response,
                        critic_feedback=None,
                        latency_ms=latency_ms,
                        error_type=error_type,
                    )
                    turns.append(turn)
                    break

            # 5. Get critic feedback (ADAPTIVE mode only)
            critic_feedback = None
            if mode == AttackMode.ADAPTIVE and self._critic is not None:
                # Create temporary turn for critic evaluation
                temp_turn = AttackTurn(
                    turn_number=turn_number,
                    payload=payload,
                    response=response,
                    critic_feedback=None,
                    latency_ms=latency_ms,
                    error_type=error_type,
                )
                temp_turns = turns + [temp_turn]
                critic_feedback = self._critic.evaluate(goal, temp_turns)

            # 6. Create the complete turn
            turn = AttackTurn(
                turn_number=turn_number,
                payload=payload,
                response=response,
                critic_feedback=critic_feedback,
                latency_ms=latency_ms,
                error_type=error_type,
            )
            turns.append(turn)

            # 7. Check if critic says to stop (strategy exhausted)
            if critic_feedback is not None and not critic_feedback.should_continue:
                break

        # Build and return result
        return AttackResult(
            goal=goal,
            persona=persona,
            success=found_exploit,
            turns=turns,
            judge_verdict=final_verdict,
            winning_payloads=winning_payloads,
        )
