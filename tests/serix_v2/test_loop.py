"""
Serix v2 - Engine Loop Tests

P1-S1-T03 to P1-S1-T07: Tests proving the engine loop logic works correctly.

These tests use mocks only - no real LLM calls.
They prove:
- Law 5: Flag-to-Logic (exhaustive, depth flags control behavior)
- Sticky Success Rule: Once exploited, success stays True
"""

from serix_v2.core.contracts import AttackMode, AttackStatus
from serix_v2.engine.adversary import AdversaryEngine

from .mocks import MockAttacker, MockCritic, MockJudge, MockTarget


class TestEngineLoop:
    """Test cases for AdversaryEngine turn loop behavior."""

    def test_stops_on_exploit_non_exhaustive(self) -> None:
        """
        P1-S1-T03: Engine stops at turn 2 when Judge says EXPLOITED (exhaustive=False).

        Setup:
        - Judge returns: DEFENDED, EXPLOITED, DEFENDED, DEFENDED, DEFENDED
        - Critic returns: True for all turns (would continue)
        - exhaustive=False

        Expected:
        - Engine stops after turn 2 (when exploit found)
        - result.success is True
        - len(result.turns) == 2
        """
        target = MockTarget(
            responses=[
                "Response 1",
                "Response 2",
                "Response 3",
                "Response 4",
                "Response 5",
            ]
        )
        attacker = MockAttacker(
            payloads=["Payload 1", "Payload 2", "Payload 3", "Payload 4", "Payload 5"]
        )
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,
                AttackStatus.EXPLOITED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
            ]
        )
        critic = MockCritic(should_continue_sequence=[True, True, True, True, True])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=critic,
        )

        result = engine.run(
            goal="Test goal",
            depth=5,
            exhaustive=False,
            mode=AttackMode.ADAPTIVE,
        )

        assert len(result.turns) == 2, f"Expected 2 turns, got {len(result.turns)}"
        assert result.success is True, "Expected success=True after exploit"
        assert (
            result.winning_payload == "Payload 2"
        ), "Expected winning payload from turn 2"

    def test_continues_on_exploit_exhaustive(self) -> None:
        """
        P1-S1-T04: Engine runs all 5 turns despite exploit at turn 2 (exhaustive=True).

        Setup:
        - Judge returns: DEFENDED, EXPLOITED, DEFENDED, DEFENDED, DEFENDED
        - Critic returns: True for all turns
        - exhaustive=True

        Expected:
        - Engine runs all 5 turns
        - result.success is True (sticky from turn 2)
        - len(result.turns) == 5
        """
        target = MockTarget(
            responses=[
                "Response 1",
                "Response 2",
                "Response 3",
                "Response 4",
                "Response 5",
            ]
        )
        attacker = MockAttacker(
            payloads=["Payload 1", "Payload 2", "Payload 3", "Payload 4", "Payload 5"]
        )
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,
                AttackStatus.EXPLOITED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
            ]
        )
        critic = MockCritic(should_continue_sequence=[True, True, True, True, True])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=critic,
        )

        result = engine.run(
            goal="Test goal",
            depth=5,
            exhaustive=True,
            mode=AttackMode.ADAPTIVE,
        )

        assert (
            len(result.turns) == 5
        ), f"Expected 5 turns in exhaustive mode, got {len(result.turns)}"
        assert result.success is True, "Expected success=True (sticky from turn 2)"

    def test_stops_when_critic_says_stop(self) -> None:
        """
        P1-S1-T05: Engine stops when Critic says should_continue=False.

        Setup:
        - Judge returns: DEFENDED for all turns (no exploit)
        - Critic returns: True, False, True, True, True (stops at turn 2)
        - exhaustive=False

        Expected:
        - Engine stops after turn 2 (critic said stop)
        - result.success is False (no exploit found)
        - len(result.turns) == 2
        """
        target = MockTarget(
            responses=[
                "Response 1",
                "Response 2",
                "Response 3",
                "Response 4",
                "Response 5",
            ]
        )
        attacker = MockAttacker(
            payloads=["Payload 1", "Payload 2", "Payload 3", "Payload 4", "Payload 5"]
        )
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
            ]
        )
        critic = MockCritic(should_continue_sequence=[True, False, True, True, True])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=critic,
        )

        result = engine.run(
            goal="Test goal",
            depth=5,
            exhaustive=False,
            mode=AttackMode.ADAPTIVE,
        )

        assert (
            len(result.turns) == 2
        ), f"Expected 2 turns (critic stopped), got {len(result.turns)}"
        assert result.success is False, "Expected success=False (no exploit found)"

    def test_runs_to_depth_limit(self) -> None:
        """
        P1-S1-T06: Engine runs exactly depth turns when no early stop.

        Setup:
        - Judge returns: DEFENDED for all turns
        - Critic returns: True for all turns (continue attacking)
        - depth=5

        Expected:
        - Engine runs all 5 turns
        - result.success is False
        - len(result.turns) == 5
        """
        target = MockTarget(
            responses=[
                "Response 1",
                "Response 2",
                "Response 3",
                "Response 4",
                "Response 5",
            ]
        )
        attacker = MockAttacker(
            payloads=["Payload 1", "Payload 2", "Payload 3", "Payload 4", "Payload 5"]
        )
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
            ]
        )
        critic = MockCritic(should_continue_sequence=[True, True, True, True, True])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=critic,
        )

        result = engine.run(
            goal="Test goal",
            depth=5,
            exhaustive=False,
            mode=AttackMode.ADAPTIVE,
        )

        assert (
            len(result.turns) == 5
        ), f"Expected 5 turns (depth limit), got {len(result.turns)}"
        assert result.success is False, "Expected success=False (all defended)"

    def test_sticky_success_in_exhaustive_mode(self) -> None:
        """
        P1-S1-T07: Once exploited, success stays True even if later turns are DEFENDED.

        Setup:
        - Judge returns: DEFENDED, EXPLOITED, DEFENDED, DEFENDED, DEFENDED
        - Critic returns: True for all turns
        - exhaustive=True

        Expected:
        - Engine runs all 5 turns
        - result.success is True (STICKY from turn 2)
        - result.winning_payload is the payload from turn 2
        """
        target = MockTarget(
            responses=[
                "Response 1",
                "Response 2",
                "Response 3",
                "Response 4",
                "Response 5",
            ]
        )
        attacker = MockAttacker(
            payloads=["Payload 1", "Payload 2", "Payload 3", "Payload 4", "Payload 5"]
        )
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,
                AttackStatus.EXPLOITED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
            ]
        )
        critic = MockCritic(should_continue_sequence=[True, True, True, True, True])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=critic,
        )

        result = engine.run(
            goal="Test goal",
            depth=5,
            exhaustive=True,
            mode=AttackMode.ADAPTIVE,
        )

        assert (
            len(result.turns) == 5
        ), f"Expected 5 turns (exhaustive), got {len(result.turns)}"
        assert result.success is True, "Expected success=True (STICKY from turn 2)"
        assert (
            result.winning_payload == "Payload 2"
        ), "Expected winning payload from turn 2"
        assert result.winning_payload is not None, "Expected winning_payload to be set"
