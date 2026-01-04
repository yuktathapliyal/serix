"""
Integration tests for ChaosInjector.

Tests the full flow of chaos injection with realistic scenarios.

Reference: Phase 9D Plan, Section 6.2
"""

from __future__ import annotations

import time

import pytest

from serix_v2.services.chaos import ChaosConfig, ChaosError, ChaosInjector, JsonMutation


class MockTarget:
    """Mock target that tracks calls and responses."""

    def __init__(self, responses: list[str] | None = None) -> None:
        self._responses = responses or ["Response 1", "Response 2", "Response 3"]
        self._call_index = 0
        self._calls: list[str] = []

    @property
    def id(self) -> str:
        return "t_integration"

    @property
    def locator(self) -> str:
        return "integration_test.py:target"

    def __call__(self, message: str) -> str:
        self._calls.append(message)
        response = self._responses[self._call_index % len(self._responses)]
        self._call_index += 1
        return response

    @property
    def calls(self) -> list[str]:
        return self._calls


@pytest.fixture
def mock_target() -> MockTarget:
    """Provide a mock target for integration tests."""
    return MockTarget()


class TestChaosIntegration:
    """Integration tests for full chaos injection flow."""

    def test_chaos_target_with_mock_target(self, mock_target: MockTarget) -> None:
        """Full flow: wrap target, make calls, verify behavior."""
        config = ChaosConfig(
            probability=0.0,  # No chaos for this test
        )
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        # Verify target protocol compliance
        assert chaos_target.id == "t_integration"
        assert chaos_target.locator == "integration_test.py:target"

        # Make calls
        result1 = chaos_target("Message 1")
        result2 = chaos_target("Message 2")

        assert result1 == "Response 1"
        assert result2 == "Response 2"
        assert mock_target.calls == ["Message 1", "Message 2"]

    def test_multiple_calls_vary_mutations(self, mock_target: MockTarget) -> None:
        """With probability=0.5, should get mix of mutated and clean calls."""
        config = ChaosConfig(
            probability=0.5,
            json_enabled=True,  # Use JSON mutation (returns corrupted, doesn't call)
            random_seed=42,
        )
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        mutated_count = 0
        clean_count = 0

        for _ in range(100):
            result = chaos_target("test")
            if result in JsonMutation.CORRUPTION_PAYLOADS:
                mutated_count += 1
            else:
                clean_count += 1

        # With probability 0.5, expect roughly 50/50 split
        # Allow some variance (30-70 range)
        assert 30 <= mutated_count <= 70
        assert 30 <= clean_count <= 70
        assert mutated_count + clean_count == 100

    def test_all_mutations_enabled(self, mock_target: MockTarget) -> None:
        """With all mutations enabled, all types should be possible."""
        config = ChaosConfig(
            probability=1.0,
            latency_enabled=True,
            latency_seconds=0.001,  # Very short for testing
            errors_enabled=True,
            json_enabled=True,
            random_seed=42,
        )
        _injector = ChaosInjector(config)  # noqa: F841 - validates config

        latency_seen = False
        error_seen = False
        json_seen = False

        # Run many iterations to see all mutation types
        for seed in range(1000):
            # Reset seed each time to explore different outcomes
            config_iter = ChaosConfig(
                probability=1.0,
                latency_enabled=True,
                latency_seconds=0.001,
                errors_enabled=True,
                json_enabled=True,
                random_seed=seed,
            )
            injector_iter = ChaosInjector(config_iter)
            target_iter = injector_iter.wrap(mock_target)

            try:
                result = target_iter("test")
                if result in JsonMutation.CORRUPTION_PAYLOADS:
                    json_seen = True
                else:
                    latency_seen = True  # Latency returns target response
            except ChaosError:
                error_seen = True

            if latency_seen and error_seen and json_seen:
                break

        assert latency_seen, "Latency mutation was never selected"
        assert error_seen, "Error mutation was never selected"
        assert json_seen, "JSON mutation was never selected"

    def test_latency_mutation_measurable(self, mock_target: MockTarget) -> None:
        """Latency mutation should actually sleep for specified time."""
        config = ChaosConfig(
            probability=1.0,
            latency_enabled=True,
            latency_seconds=0.1,  # 100ms delay
            errors_enabled=False,
            json_enabled=False,
            random_seed=42,
        )
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        start = time.perf_counter()
        result = chaos_target("test")
        elapsed = time.perf_counter() - start

        assert elapsed >= 0.1
        assert elapsed < 0.2  # Some tolerance
        assert result == "Response 1"  # Target was called

    def test_error_mutation_catchable(self, mock_target: MockTarget) -> None:
        """ChaosError should be catchable with error_code accessible."""
        config = ChaosConfig(
            probability=1.0,
            latency_enabled=False,
            errors_enabled=True,
            json_enabled=False,
            random_seed=42,
        )
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        with pytest.raises(ChaosError) as exc_info:
            chaos_target("test")

        # Error code should be accessible
        assert exc_info.value.error_code in [500, 503, 429]
        assert isinstance(exc_info.value.error_code, int)

    def test_json_mutation_output_malformed(self, mock_target: MockTarget) -> None:
        """JSON mutation should return strings that would break JSON parsers."""
        import json

        malformed_count = 0
        for seed in range(50):
            config_iter = ChaosConfig(
                probability=1.0,
                json_enabled=True,
                random_seed=seed,
            )
            injector_iter = ChaosInjector(config_iter)
            target_iter = injector_iter.wrap(mock_target)

            result = target_iter("test")

            # Try to parse as JSON
            if result == "":
                malformed_count += 1  # Empty is "malformed" for JSON
            else:
                try:
                    json.loads(result)
                    # If it parses, check if it's the schema violation one
                    if result == '{"count": "not_a_number"}':
                        malformed_count += 1  # Schema violation
                except json.JSONDecodeError:
                    malformed_count += 1  # Truly malformed

        # All corruption payloads should be "malformed" in some sense
        assert malformed_count == 50


class TestChaosTargetUnwrapped:
    """Tests for unwrapped property transparency."""

    def test_unwrapped_provides_access_without_chaos(
        self, mock_target: MockTarget
    ) -> None:
        """unwrapped should allow accessing target without mutation."""
        config = ChaosConfig(
            probability=1.0,
            json_enabled=True,  # Would return corrupted
        )
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        # Direct call through chaos_target would be mutated
        # But unwrapped gives us direct access
        unwrapped = chaos_target.unwrapped

        assert unwrapped is mock_target
        result = unwrapped("test")
        assert result == "Response 1"  # Not corrupted
