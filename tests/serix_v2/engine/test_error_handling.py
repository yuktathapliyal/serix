"""
FH-01: Error Handling Tests for AdversaryEngine

Ensures the engine survives target crashes and records them as data points.
"""

from serix_v2.core.contracts import AttackMode, AttackStatus
from serix_v2.engine.adversary import AdversaryEngine

from ..mocks import MockAttacker, MockCrashingTarget, MockJudge, MockTarget


class TestEngineSurvivesTargetCrash:
    """Engine should not crash when target throws exceptions."""

    def test_engine_survives_value_error(self) -> None:
        """Engine continues when target throws ValueError."""
        target = MockCrashingTarget(
            crash_on_calls=[0],
            exception_type=ValueError,
            exception_message="Invalid input!",
        )
        attacker = MockAttacker(payloads=["Payload 1"])
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=1, mode=AttackMode.STATIC)

        # Engine should complete without crashing
        assert result is not None
        assert len(result.turns) == 1

    def test_engine_survives_runtime_error(self) -> None:
        """Engine continues when target throws RuntimeError."""
        target = MockCrashingTarget(
            crash_on_calls=[0],
            exception_type=RuntimeError,
            exception_message="Something went wrong!",
        )
        attacker = MockAttacker(payloads=["Payload 1"])
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=1, mode=AttackMode.STATIC)

        assert result is not None
        assert len(result.turns) == 1

    def test_engine_survives_timeout_error(self) -> None:
        """Engine continues when target throws TimeoutError."""
        target = MockCrashingTarget(
            crash_on_calls=[0],
            exception_type=TimeoutError,
            exception_message="Request timed out!",
        )
        attacker = MockAttacker(payloads=["Payload 1"])
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=1, mode=AttackMode.STATIC)

        assert result is not None
        assert len(result.turns) == 1


class TestErrorRecordedInTurn:
    """Error information should be captured in AttackTurn."""

    def test_error_type_populated_on_exception(self) -> None:
        """error_type field is set to exception class name."""
        target = MockCrashingTarget(
            crash_on_calls=[0],
            exception_type=ValueError,
            exception_message="Bad value!",
        )
        attacker = MockAttacker(payloads=["Payload 1"])
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=1, mode=AttackMode.STATIC)

        assert result.turns[0].error_type == "ValueError"

    def test_error_message_in_response(self) -> None:
        """Error message should appear in response field."""
        target = MockCrashingTarget(
            crash_on_calls=[0],
            exception_type=RuntimeError,
            exception_message="Custom error message",
        )
        attacker = MockAttacker(payloads=["Payload 1"])
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=1, mode=AttackMode.STATIC)

        assert "[TARGET_ERROR]" in result.turns[0].response
        assert "RuntimeError" in result.turns[0].response
        assert "Custom error message" in result.turns[0].response

    def test_error_type_none_on_success(self) -> None:
        """error_type should be None when target succeeds."""
        target = MockTarget(responses=["Normal response"])
        attacker = MockAttacker(payloads=["Payload 1"])
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=1, mode=AttackMode.STATIC)

        assert result.turns[0].error_type is None


class TestEngineContinuesAfterError:
    """Engine should continue attacking after an error."""

    def test_continues_to_subsequent_turns(self) -> None:
        """Engine runs remaining turns after a crash."""
        # Crash on turn 1, succeed on turns 2 and 3
        target = MockCrashingTarget(
            crash_on_calls=[0],
            fallback_response="Normal response",
        )
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

        assert len(result.turns) == 3
        # First turn had error
        assert result.turns[0].error_type == "ValueError"
        # Subsequent turns succeeded
        assert result.turns[1].error_type is None
        assert result.turns[2].error_type is None

    def test_multiple_crashes_still_completes(self) -> None:
        """Engine survives multiple target crashes."""
        # Crash on turns 1 and 3, succeed on turn 2
        target = MockCrashingTarget(
            crash_on_calls=[0, 2],
            fallback_response="Normal response",
        )
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

        assert len(result.turns) == 3
        assert result.turns[0].error_type == "ValueError"
        assert result.turns[1].error_type is None
        assert result.turns[2].error_type == "ValueError"


class TestJudgeEvaluatesErrorResponse:
    """Judge should evaluate error responses (typically as DEFENDED)."""

    def test_judge_receives_error_response(self) -> None:
        """Judge evaluates the error response text."""
        target = MockCrashingTarget(
            crash_on_calls=[0],
            exception_type=ValueError,
            exception_message="Crash!",
        )
        attacker = MockAttacker(payloads=["Payload 1"])
        # Judge will still be called and return DEFENDED
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])

        engine = AdversaryEngine(target, attacker, judge)
        result = engine.run("test goal", depth=1, mode=AttackMode.STATIC)

        # Judge was called (mock incremented)
        assert result.judge_verdict is not None
        assert result.judge_verdict.verdict == AttackStatus.DEFENDED
