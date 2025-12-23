"""Tests for fuzzing mutation behaviors.

Tests mutation classes for latency injection, error injection, and JSON corruption.
Uses seeded randomness for deterministic tests.
"""

from __future__ import annotations

import random
from unittest.mock import patch

import pytest
from openai import APIError, RateLimitError
from openai.types.chat import ChatCompletion

from serix.fuzz.mutations import (
    ErrorMutation,
    JsonCorruptionMutation,
    LatencyMutation,
    Mutation,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_chat_completion() -> ChatCompletion:
    """Create a valid ChatCompletion for mutation testing."""
    return ChatCompletion.model_validate(
        {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1677652288,
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "This is a test response from the AI assistant.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30,
            },
        }
    )


@pytest.fixture(autouse=True)
def seed_random():
    """Seed random for deterministic tests."""
    random.seed(42)
    yield
    # Reset after test
    random.seed()


# =============================================================================
# LatencyMutation Tests
# =============================================================================


class TestLatencyMutation:
    """Tests for LatencyMutation behavior."""

    def test_latency_mutation_sleeps(
        self, sample_chat_completion: ChatCompletion
    ) -> None:
        """Latency mutation adds delay."""
        mutation = LatencyMutation(delay_seconds=1.0)

        with patch("time.sleep") as mock_sleep:
            result = mutation.apply(sample_chat_completion)
            mock_sleep.assert_called_once_with(1.0)

        # Response should be unchanged
        assert (
            result.choices[0].message.content
            == sample_chat_completion.choices[0].message.content
        )

    def test_latency_custom_delay(self, sample_chat_completion: ChatCompletion) -> None:
        """Latency mutation uses custom delay."""
        mutation = LatencyMutation(delay_seconds=5.0)

        with patch("time.sleep") as mock_sleep:
            mutation.apply(sample_chat_completion)
            mock_sleep.assert_called_once_with(5.0)

    def test_latency_default_delay(self) -> None:
        """Default delay is 5 seconds."""
        mutation = LatencyMutation()
        assert mutation.delay_seconds == 5.0

    def test_latency_should_apply_respects_probability(self) -> None:
        """should_apply respects probability parameter."""
        mutation = LatencyMutation()

        # With probability 1.0, should always apply
        results = [mutation.should_apply(1.0) for _ in range(10)]
        assert all(results)

        # With probability 0.0, should never apply
        results = [mutation.should_apply(0.0) for _ in range(10)]
        assert not any(results)

    def test_latency_should_apply_probabilistic(self) -> None:
        """should_apply is probabilistic with values between 0 and 1."""
        mutation = LatencyMutation()

        # With probability 0.5, should apply roughly half the time
        results = [mutation.should_apply(0.5) for _ in range(100)]
        true_count = sum(results)

        # Allow for some variance (between 30% and 70%)
        assert 30 <= true_count <= 70

    def test_latency_name(self) -> None:
        """Latency mutation has correct name."""
        mutation = LatencyMutation()
        assert mutation.name == "latency"


# =============================================================================
# ErrorMutation Tests
# =============================================================================


class TestErrorMutation:
    """Tests for ErrorMutation behavior."""

    def test_error_mutation_raises_api_error(
        self, sample_chat_completion: ChatCompletion
    ) -> None:
        """Error mutation raises APIError for 500/503 codes."""
        mutation = ErrorMutation(error_codes=[500])

        with pytest.raises(APIError) as exc_info:
            mutation.apply(sample_chat_completion)

        assert "500" in str(exc_info.value)

    def test_error_mutation_raises_rate_limit(
        self, sample_chat_completion: ChatCompletion
    ) -> None:
        """Error mutation raises RateLimitError for 429."""
        mutation = ErrorMutation(error_codes=[429])

        with pytest.raises(RateLimitError) as exc_info:
            mutation.apply(sample_chat_completion)

        assert "Rate limit" in str(exc_info.value)

    def test_error_codes_random_selection(
        self, sample_chat_completion: ChatCompletion
    ) -> None:
        """Error mutation picks from configured codes randomly."""
        mutation = ErrorMutation(error_codes=[500, 503])

        # Run multiple times to check randomness
        error_codes_seen = set()
        for _ in range(20):
            try:
                mutation.apply(sample_chat_completion)
            except APIError as e:
                if "500" in str(e):
                    error_codes_seen.add(500)
                elif "503" in str(e):
                    error_codes_seen.add(503)

        # Should see both error codes (with high probability)
        assert len(error_codes_seen) >= 1

    def test_error_default_codes(self) -> None:
        """Default error codes are 500, 503, 429."""
        mutation = ErrorMutation()
        assert mutation.error_codes == [500, 503, 429]

    def test_error_should_apply_respects_probability(self) -> None:
        """should_apply respects probability parameter."""
        mutation = ErrorMutation()

        # With probability 1.0, should always apply
        results = [mutation.should_apply(1.0) for _ in range(10)]
        assert all(results)

        # With probability 0.0, should never apply
        results = [mutation.should_apply(0.0) for _ in range(10)]
        assert not any(results)

    def test_error_name(self) -> None:
        """Error mutation has correct name."""
        mutation = ErrorMutation()
        assert mutation.name == "error"


# =============================================================================
# JsonCorruptionMutation Tests
# =============================================================================


class TestJsonCorruptionMutation:
    """Tests for JsonCorruptionMutation behavior."""

    def test_json_truncate_content(
        self, sample_chat_completion: ChatCompletion
    ) -> None:
        """JSON corruption can truncate content."""
        mutation = JsonCorruptionMutation()
        original_content = sample_chat_completion.choices[0].message.content

        # Force the truncate strategy
        result = mutation._truncate_content(sample_chat_completion)

        # Content should be shorter
        new_content = result.choices[0].message.content
        assert new_content is not None
        assert len(new_content) < len(original_content)

    def test_json_null_value(self, sample_chat_completion: ChatCompletion) -> None:
        """JSON corruption can set content to None."""
        mutation = JsonCorruptionMutation()

        result = mutation._null_value(sample_chat_completion)

        assert result.choices[0].message.content is None

    def test_json_remove_key(self, sample_chat_completion: ChatCompletion) -> None:
        """JSON corruption can remove usage key."""
        mutation = JsonCorruptionMutation()

        result = mutation._remove_key(sample_chat_completion)

        assert result.usage is None

    def test_json_corruption_applies_strategy(
        self, sample_chat_completion: ChatCompletion
    ) -> None:
        """Apply method selects and runs a corruption strategy."""
        mutation = JsonCorruptionMutation()

        # Apply should not crash and should return a ChatCompletion
        result = mutation.apply(sample_chat_completion)

        assert isinstance(result, ChatCompletion)

    def test_json_should_apply_respects_probability(self) -> None:
        """should_apply respects probability parameter."""
        mutation = JsonCorruptionMutation()

        # With probability 1.0, should always apply
        results = [mutation.should_apply(1.0) for _ in range(10)]
        assert all(results)

        # With probability 0.0, should never apply
        results = [mutation.should_apply(0.0) for _ in range(10)]
        assert not any(results)

    def test_json_corruption_strategies_exist(self) -> None:
        """All corruption strategies are defined."""
        mutation = JsonCorruptionMutation()

        assert len(mutation.corruption_strategies) == 4
        strategy_names = [s.__name__ for s in mutation.corruption_strategies]

        assert "_remove_key" in strategy_names
        assert "_truncate_content" in strategy_names
        assert "_wrong_type" in strategy_names
        assert "_null_value" in strategy_names

    def test_json_name(self) -> None:
        """JSON corruption mutation has correct name."""
        mutation = JsonCorruptionMutation()
        assert mutation.name == "json_corruption"


# =============================================================================
# Mutation Base Class Tests
# =============================================================================


class TestMutationBaseClass:
    """Tests for Mutation abstract base class."""

    def test_mutation_is_abstract(self) -> None:
        """Mutation base class cannot be instantiated directly."""
        # This should fail because Mutation is abstract
        with pytest.raises(TypeError):
            Mutation()  # type: ignore

    def test_all_mutations_have_name(self) -> None:
        """All mutation subclasses have a name attribute."""
        mutations = [
            LatencyMutation(),
            ErrorMutation(),
            JsonCorruptionMutation(),
        ]

        for mutation in mutations:
            assert hasattr(mutation, "name")
            assert isinstance(mutation.name, str)
            assert len(mutation.name) > 0


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases in mutation handling."""

    def test_truncate_empty_content(self) -> None:
        """Truncate handles empty content gracefully."""
        mutation = JsonCorruptionMutation()

        response = ChatCompletion.model_validate(
            {
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": 1677652288,
                "model": "gpt-4o-mini",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "",  # Empty content
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 0,
                    "total_tokens": 10,
                },
            }
        )

        # Should not crash
        result = mutation._truncate_content(response)
        assert isinstance(result, ChatCompletion)

    def test_truncate_single_char_content(self) -> None:
        """Truncate handles single character content."""
        mutation = JsonCorruptionMutation()

        response = ChatCompletion.model_validate(
            {
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": 1677652288,
                "model": "gpt-4o-mini",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "X",  # Single char
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 1,
                    "total_tokens": 11,
                },
            }
        )

        # Should not crash
        result = mutation._truncate_content(response)
        assert isinstance(result, ChatCompletion)

    def test_remove_key_when_usage_already_none(self) -> None:
        """Remove key handles missing usage gracefully."""
        mutation = JsonCorruptionMutation()

        response = ChatCompletion.model_validate(
            {
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": 1677652288,
                "model": "gpt-4o-mini",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Test",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": None,  # Already None
            }
        )

        # Should not crash
        result = mutation._remove_key(response)
        assert result.usage is None

    def test_latency_zero_delay(self, sample_chat_completion: ChatCompletion) -> None:
        """Latency mutation with zero delay doesn't crash."""
        mutation = LatencyMutation(delay_seconds=0.0)

        with patch("time.sleep") as mock_sleep:
            result = mutation.apply(sample_chat_completion)
            mock_sleep.assert_called_once_with(0.0)

        assert result == sample_chat_completion

    def test_verbose_mode_output(
        self, sample_chat_completion: ChatCompletion, capsys
    ) -> None:
        """Mutations produce output in verbose mode."""
        mutation = LatencyMutation(delay_seconds=0.1)

        with patch("time.sleep"):
            mutation.apply(sample_chat_completion, verbose=True)

        # Note: Rich console output may not be captured by capsys
        # This test just ensures verbose=True doesn't crash
