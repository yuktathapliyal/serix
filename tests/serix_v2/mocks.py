"""
Serix v2 - Mock Implementations for Testing

P1-S1-T02: Mock implementations of all protocols for testing the engine
without real LLM calls.

These mocks are controllable via constructor parameters, allowing tests
to script exact behavior sequences.
"""

from serix_v2.core.contracts import (
    AttackStatus,
    AttackTurn,
    CriticFeedback,
    JudgeVerdict,
)


class MockTarget:
    """
    Mock implementation of the Target protocol.

    Returns configurable responses in sequence.
    """

    def __init__(
        self,
        target_id: str = "t_mock1234",
        locator: str = "mock_target.py:mock_fn",
        responses: list[str] | None = None,
    ):
        self._id = target_id
        self._locator = locator
        self._responses = responses or ["Mock response"]
        self._call_count = 0

    @property
    def id(self) -> str:
        return self._id

    @property
    def locator(self) -> str:
        return self._locator

    def __call__(self, message: str) -> str:
        """Return the next response in sequence, cycling if needed."""
        response = self._responses[self._call_count % len(self._responses)]
        self._call_count += 1
        return response


class MockAttacker:
    """
    Mock implementation of the Attacker protocol.

    Returns configurable payloads in sequence.
    """

    def __init__(self, payloads: list[str] | None = None):
        self._payloads = payloads or ["Mock attack payload"]
        self._call_count = 0

    def generate(self, goal: str, history: list[AttackTurn]) -> str:
        """Return the next payload in sequence, cycling if needed."""
        payload = self._payloads[self._call_count % len(self._payloads)]
        self._call_count += 1
        return payload


class MockJudge:
    """
    Mock implementation of the Judge protocol.

    Returns configurable verdicts (EXPLOITED/DEFENDED) in sequence.
    This is what determines if an attack succeeded - NOT the Critic.
    """

    def __init__(self, verdicts: list[AttackStatus] | None = None):
        self._verdicts = verdicts or [AttackStatus.DEFENDED]
        self._call_count = 0

    def evaluate(self, goal: str, payload: str, response: str) -> JudgeVerdict:
        """Return the next verdict in sequence, cycling if needed."""
        verdict = self._verdicts[self._call_count % len(self._verdicts)]
        self._call_count += 1
        return JudgeVerdict(
            verdict=verdict,
            confidence=1.0,
            reasoning=f"Mock verdict: {verdict.value}",
        )


class MockCritic:
    """
    Mock implementation of the Critic protocol.

    Returns configurable should_continue values in sequence.
    The Critic advises on strategy, NOT on whether an attack succeeded.
    """

    def __init__(self, should_continue_sequence: list[bool] | None = None):
        self._should_continue = should_continue_sequence or [True]
        self._call_count = 0

    def evaluate(self, goal: str, turns: list[AttackTurn]) -> CriticFeedback:
        """Return the next feedback in sequence, cycling if needed."""
        should_continue = self._should_continue[
            self._call_count % len(self._should_continue)
        ]
        self._call_count += 1
        return CriticFeedback(
            should_continue=should_continue,
            confidence=0.8,
            reasoning=f"Mock critic: should_continue={should_continue}",
            suggested_pivot="Try a different approach" if should_continue else None,
        )


class MockCrashingTarget:
    """
    Mock target that throws exceptions on specified calls.

    FH-01: Used to test engine error handling.
    """

    def __init__(
        self,
        target_id: str = "t_crash1234",
        locator: str = "crash_target.py:crash_fn",
        crash_on_calls: list[int] | None = None,
        exception_type: type[Exception] = ValueError,
        exception_message: str = "Target crashed!",
        fallback_response: str = "Normal response",
    ):
        self._id = target_id
        self._locator = locator
        self._crash_on_calls = crash_on_calls or [0]  # Crash on first call by default
        self._exception_type = exception_type
        self._exception_message = exception_message
        self._fallback_response = fallback_response
        self._call_count = 0

    @property
    def id(self) -> str:
        return self._id

    @property
    def locator(self) -> str:
        return self._locator

    def __call__(self, message: str) -> str:
        """Throw exception on specified calls, return fallback otherwise."""
        current_call = self._call_count
        self._call_count += 1

        if current_call in self._crash_on_calls:
            raise self._exception_type(self._exception_message)

        return self._fallback_response
