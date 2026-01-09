"""
FH-02: Exhaustive Mode Winning Payloads Tests

Ensures the engine captures ALL winning payloads in exhaustive mode,
not just the first one.
"""

from serix_v2.core.contracts import AttackMode, AttackStatus
from serix_v2.engine.adversary import AdversaryEngine

from ..mocks import MockAttacker, MockJudge, MockTarget


class TestExhaustiveCapturesAllPayloads:
    """Exhaustive mode should capture all winning payloads."""

    def test_captures_multiple_winning_payloads(self) -> None:
        """All exploits are recorded in winning_payloads list."""
        target = MockTarget(responses=["R1", "R2", "R3", "R4", "R5"])
        attacker = MockAttacker(payloads=["P1", "P2", "P3", "P4", "P5"])
        # Exploit on turns 2 and 4
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,  # P1
                AttackStatus.EXPLOITED,  # P2 - first exploit
                AttackStatus.DEFENDED,  # P3
                AttackStatus.EXPLOITED,  # P4 - second exploit
                AttackStatus.DEFENDED,  # P5
            ]
        )

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run(
            "test goal", depth=5, exhaustive=True, mode=AttackMode.STATIC
        )

        # Should capture both winning payloads
        assert len(result.winning_payloads) == 2
        assert "P2" in result.winning_payloads
        assert "P4" in result.winning_payloads

    def test_order_preserved(self) -> None:
        """Winning payloads are in order of discovery."""
        target = MockTarget(responses=["R1", "R2", "R3"])
        attacker = MockAttacker(payloads=["First", "Second", "Third"])
        # All three are exploits
        judge = MockJudge(
            verdicts=[
                AttackStatus.EXPLOITED,
                AttackStatus.EXPLOITED,
                AttackStatus.EXPLOITED,
            ]
        )

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run(
            "test goal", depth=3, exhaustive=True, mode=AttackMode.STATIC
        )

        assert result.winning_payloads == ["First", "Second", "Third"]


class TestNonExhaustiveSinglePayload:
    """Non-exhaustive mode should stop early and capture single payload."""

    def test_stops_on_first_exploit(self) -> None:
        """Non-exhaustive stops on first exploit, captures one payload."""
        target = MockTarget(responses=["R1", "R2", "R3"])
        attacker = MockAttacker(payloads=["P1", "P2", "P3"])
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,
                AttackStatus.EXPLOITED,  # Should stop here
                AttackStatus.EXPLOITED,  # Never reached
            ]
        )

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run(
            "test goal", depth=3, exhaustive=False, mode=AttackMode.STATIC
        )

        # Only 2 turns executed (stopped on exploit)
        assert len(result.turns) == 2
        # Only one winning payload
        assert len(result.winning_payloads) == 1
        assert result.winning_payloads[0] == "P2"


class TestBackwardsCompatibleProperty:
    """winning_payload property should return first payload."""

    def test_property_returns_first_payload(self) -> None:
        """winning_payload property returns first from list."""
        target = MockTarget(responses=["R1", "R2", "R3"])
        attacker = MockAttacker(payloads=["First", "Second", "Third"])
        judge = MockJudge(
            verdicts=[
                AttackStatus.EXPLOITED,  # First
                AttackStatus.EXPLOITED,  # Second
                AttackStatus.EXPLOITED,  # Third
            ]
        )

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run(
            "test goal", depth=3, exhaustive=True, mode=AttackMode.STATIC
        )

        # Property returns first
        assert result.winning_payload == "First"
        # List has all
        assert len(result.winning_payloads) == 3

    def test_property_returns_none_when_empty(self) -> None:
        """winning_payload property returns None when no exploits."""
        target = MockTarget(responses=["R1", "R2"])
        attacker = MockAttacker(payloads=["P1", "P2"])
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED, AttackStatus.DEFENDED])

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=2, mode=AttackMode.STATIC)

        assert result.winning_payload is None
        assert result.winning_payloads == []


class TestEmptyListOnNoExploit:
    """No exploits should result in empty winning_payloads list."""

    def test_empty_list_on_all_defended(self) -> None:
        """winning_payloads is empty when all turns are DEFENDED."""
        target = MockTarget(responses=["R1", "R2", "R3"])
        attacker = MockAttacker(payloads=["P1", "P2", "P3"])
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
                AttackStatus.DEFENDED,
            ]
        )

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=3, mode=AttackMode.STATIC)

        assert result.winning_payloads == []
        assert result.success is False


class TestStickySuccessStillWorks:
    """Sticky success rule should work with new winning_payloads."""

    def test_success_stays_true_after_defended(self) -> None:
        """Once success=True, it stays True even after DEFENDED turns."""
        target = MockTarget(responses=["R1", "R2", "R3", "R4"])
        attacker = MockAttacker(payloads=["P1", "P2", "P3", "P4"])
        judge = MockJudge(
            verdicts=[
                AttackStatus.DEFENDED,
                AttackStatus.EXPLOITED,  # Success = True now
                AttackStatus.DEFENDED,  # Still success = True
                AttackStatus.DEFENDED,  # Still success = True
            ]
        )

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run(
            "test goal", depth=4, exhaustive=True, mode=AttackMode.STATIC
        )

        assert result.success is True
        assert len(result.winning_payloads) == 1
        assert result.winning_payloads[0] == "P2"
