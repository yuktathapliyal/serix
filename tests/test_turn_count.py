"""Test to verify turn count accuracy in adversary results.

This test mocks the critic to control exactly which turn triggers an exploit,
then verifies the reported turns_taken matches the actual turn.
"""

from unittest.mock import MagicMock

import pytest

from serix.fuzz.adversary import AdversaryLoop, CriticFeedback
from serix.fuzz.personas.jailbreaker import JailbreakerPersona


class MockTarget:
    """Mock target that always returns a fixed response."""

    def __init__(self, response: str = "I cannot help with that."):
        self.response = response
        self.call_count = 0

    def send(self, message: str):
        self.call_count += 1
        result = MagicMock()
        result.content = self.response
        result.latency_ms = 100
        return result


@pytest.fixture
def mock_client():
    """Create a mock OpenAI client."""
    client = MagicMock()
    # Mock the judge to always say EXPLOITED
    judge_response = MagicMock()
    judge_response.choices = [MagicMock()]
    judge_response.choices[
        0
    ].message.content = """
    VERDICT: EXPLOITED
    CONFIDENCE: HIGH
    VULNERABILITY_TYPE: jailbreak
    REASONING: The agent was exploited.
    """
    client.chat.completions.create.return_value = judge_response
    return client


def test_turn_count_matches_actual_exploit_turn(mock_client):
    """Verify turns_taken reflects the actual turn where exploit was detected."""

    # Track which turn we're on
    turn_counter = {"current": 0}
    exploit_on_turn = 3  # We want the exploit to happen on turn 3

    persona = JailbreakerPersona(mock_client)

    # Create adversary with fail_fast=True (stop on first exploit)
    adversary = AdversaryLoop(
        attacker_client=mock_client,
        personas=[persona],
        max_turns=5,
        verbose=False,
        fail_fast=True,
    )

    # Mock the critic to return EXPLOITED only on the specified turn
    _original_call_critic = adversary._call_critic  # noqa: F841 - saved for reference

    def mock_critic(goal: str, payload: str, response: str) -> CriticFeedback:
        turn_counter["current"] += 1
        current_turn = turn_counter["current"]

        if current_turn >= exploit_on_turn:
            return CriticFeedback(
                likely_exploited=True,
                confidence="high",
                failure_reason=None,
                suggested_pivot="",
            )
        else:
            return CriticFeedback(
                likely_exploited=False,
                confidence="high",
                failure_reason="Agent refused",
                suggested_pivot="Try a different approach",
            )

    adversary._call_critic = mock_critic

    # Run the attack
    target = MockTarget()
    result = adversary.attack(target, "test goal", persona)

    # Verify the turn count
    print("\n=== Turn Count Test ===")
    print(f"Exploit configured on turn: {exploit_on_turn}")
    print(f"Reported turns_taken: {result.turns_taken}")
    print(f"Target was called: {target.call_count} times")
    print(f"Result success: {result.success}")

    assert (
        result.turns_taken == exploit_on_turn
    ), f"turns_taken should be {exploit_on_turn}, got {result.turns_taken}"
    assert (
        target.call_count == exploit_on_turn
    ), f"Target should be called {exploit_on_turn} times, was called {target.call_count}"


@pytest.mark.parametrize("exploit_turn", [1, 2, 3, 4])
def test_turn_count_parametrized(mock_client, exploit_turn):
    """Test turn count accuracy across different exploit turns."""

    turn_counter = {"current": 0}
    persona = JailbreakerPersona(mock_client)

    adversary = AdversaryLoop(
        attacker_client=mock_client,
        personas=[persona],
        max_turns=5,
        verbose=False,
        fail_fast=True,
    )

    def mock_critic(goal: str, payload: str, response: str) -> CriticFeedback:
        turn_counter["current"] += 1
        exploited = turn_counter["current"] >= exploit_turn
        return CriticFeedback(
            likely_exploited=exploited,
            confidence="high",
            failure_reason=None if exploited else "Agent refused",
            suggested_pivot="",
        )

    adversary._call_critic = mock_critic

    target = MockTarget()
    result = adversary.attack(target, "test goal", persona)

    print(f"Exploit on turn {exploit_turn}: turns_taken={result.turns_taken}")

    assert (
        result.turns_taken == exploit_turn
    ), f"Expected turns_taken={exploit_turn}, got {result.turns_taken}"


if __name__ == "__main__":
    # Run directly for quick verification
    from unittest.mock import MagicMock

    client = MagicMock()
    judge_response = MagicMock()
    judge_response.choices = [MagicMock()]
    judge_response.choices[0].message.content = "VERDICT: EXPLOITED\nCONFIDENCE: HIGH"
    client.chat.completions.create.return_value = judge_response

    print("Running turn count verification tests...\n")

    for exploit_turn in [1, 2, 3, 4]:
        turn_counter = {"current": 0}
        persona = JailbreakerPersona(client)

        adversary = AdversaryLoop(
            attacker_client=client,
            personas=[persona],
            max_turns=5,
            verbose=False,
            fail_fast=True,
        )

        def make_mock_critic(target_turn):
            counter = {"n": 0}

            def mock_critic(goal, payload, response):
                counter["n"] += 1
                exploited = counter["n"] >= target_turn
                return CriticFeedback(
                    likely_exploited=exploited,
                    confidence="high",
                    failure_reason=None if exploited else "Refused",
                    suggested_pivot="",
                )

            return mock_critic

        adversary._call_critic = make_mock_critic(exploit_turn)

        target = MockTarget()
        result = adversary.attack(target, "test goal", persona)

        status = "✓" if result.turns_taken == exploit_turn else "✗"
        print(
            f"{status} Exploit on turn {exploit_turn}: turns_taken={result.turns_taken}"
        )

        if result.turns_taken != exploit_turn:
            print(f"  BUG DETECTED: Expected {exploit_turn}, got {result.turns_taken}")
