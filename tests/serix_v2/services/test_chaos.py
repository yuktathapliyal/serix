"""
Unit tests for ChaosInjector and chaos mutations.

Tests cover:
- ChaosConfig validation and creation
- Individual mutation behavior
- ChaosInjector probability logic
- ChaosTarget protocol compliance
- Law compliance verification

Reference: Phase 9D Plan, Section 6.1
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.protocols import Target
from serix_v2.services.chaos import (
    ChaosConfig,
    ChaosError,
    ChaosInjector,
    ChaosTarget,
    ErrorMutation,
    JsonMutation,
    LatencyMutation,
    Mutation,
)

if TYPE_CHECKING:
    pass


# ============================================================================
# TEST FIXTURES
# ============================================================================


class MockTarget:
    """Mock target for testing that implements Target protocol."""

    def __init__(self, response: str = "Hello from target") -> None:
        self._response = response
        self._call_count = 0
        self._last_message: str | None = None

    @property
    def id(self) -> str:
        return "t_mock123"

    @property
    def locator(self) -> str:
        return "mock_agent.py:mock_fn"

    def __call__(self, message: str) -> str:
        self._call_count += 1
        self._last_message = message
        return self._response

    @property
    def call_count(self) -> int:
        return self._call_count


@pytest.fixture
def mock_target() -> MockTarget:
    """Provide a fresh mock target for each test."""
    return MockTarget()


@pytest.fixture
def basic_chaos_config() -> ChaosConfig:
    """Provide a basic ChaosConfig with all mutations enabled."""
    return ChaosConfig(
        probability=1.0,
        latency_enabled=True,
        latency_seconds=0.01,  # Fast for testing
        errors_enabled=True,
        json_enabled=True,
        random_seed=42,
    )


# ============================================================================
# CHAOS ERROR TESTS
# ============================================================================


class TestChaosError:
    """Tests for ChaosError exception."""

    def test_chaos_error_stores_error_code(self) -> None:
        """ChaosError should store the HTTP-like error code."""
        error = ChaosError(500, "Internal Server Error")
        assert error.error_code == 500

    def test_chaos_error_message(self) -> None:
        """ChaosError should include error code in string representation."""
        error = ChaosError(429, "Rate limited")
        assert "429" in str(error)
        assert "Rate limited" in str(error)

    def test_chaos_error_is_catchable(self) -> None:
        """ChaosError should be catchable as Exception."""
        with pytest.raises(ChaosError) as exc_info:
            raise ChaosError(503, "Service Unavailable")
        assert exc_info.value.error_code == 503


# ============================================================================
# CHAOS CONFIG TESTS
# ============================================================================


class TestChaosConfig:
    """Tests for ChaosConfig Pydantic model."""

    def test_chaos_config_defaults(self) -> None:
        """Default values should match spec."""
        config = ChaosConfig()
        assert config.probability == 0.5
        assert config.latency_enabled is False
        assert config.latency_seconds == 5.0
        assert config.errors_enabled is False
        assert config.json_enabled is False
        assert config.random_seed is None

    def test_chaos_config_probability_validation_min(self) -> None:
        """Probability below 0.0 should raise ValidationError."""
        with pytest.raises(ValidationError):
            ChaosConfig(probability=-0.1)

    def test_chaos_config_probability_validation_max(self) -> None:
        """Probability above 1.0 should raise ValidationError."""
        with pytest.raises(ValidationError):
            ChaosConfig(probability=1.5)

    def test_chaos_config_probability_bounds(self) -> None:
        """Probability at bounds (0.0 and 1.0) should be valid."""
        config_zero = ChaosConfig(probability=0.0)
        config_one = ChaosConfig(probability=1.0)
        assert config_zero.probability == 0.0
        assert config_one.probability == 1.0

    def test_chaos_config_latency_validation(self) -> None:
        """Latency seconds must be positive."""
        with pytest.raises(ValidationError):
            ChaosConfig(latency_seconds=0.0)
        with pytest.raises(ValidationError):
            ChaosConfig(latency_seconds=-1.0)

    def test_chaos_config_from_session_config(self) -> None:
        """from_session_config() should map SerixSessionConfig fields correctly."""
        session_config = SerixSessionConfig(
            target_path="agent.py:fn",
            fuzz_probability=0.7,
            fuzz_latency=3.0,
            fuzz_errors=True,
            fuzz_json=True,
        )
        chaos_config = ChaosConfig.from_session_config(session_config)

        assert chaos_config.probability == 0.7
        assert chaos_config.latency_enabled is True
        assert chaos_config.latency_seconds == 3.0
        assert chaos_config.errors_enabled is True
        assert chaos_config.json_enabled is True

    def test_chaos_config_from_session_with_fuzz_flag(self) -> None:
        """--fuzz flag should enable all mutations."""
        session_config = SerixSessionConfig(
            target_path="agent.py:fn",
            fuzz=True,
        )
        chaos_config = ChaosConfig.from_session_config(session_config)

        assert chaos_config.latency_enabled is True
        assert chaos_config.errors_enabled is True
        assert chaos_config.json_enabled is True

    def test_chaos_config_from_session_defaults(self) -> None:
        """Without fuzz flags, mutations should be disabled."""
        session_config = SerixSessionConfig(target_path="agent.py:fn")
        chaos_config = ChaosConfig.from_session_config(session_config)

        assert chaos_config.latency_enabled is False
        assert chaos_config.errors_enabled is False
        assert chaos_config.json_enabled is False


# ============================================================================
# MUTATION TESTS - LATENCY
# ============================================================================


class TestLatencyMutation:
    """Tests for LatencyMutation."""

    def test_latency_mutation_name(self) -> None:
        """Mutation name should be 'latency'."""
        mutation = LatencyMutation()
        assert mutation.name == "latency"

    def test_latency_mutation_applies_delay(self, mock_target: MockTarget) -> None:
        """LatencyMutation should sleep before calling target."""
        import random

        mutation = LatencyMutation(delay_seconds=0.1)
        rng = random.Random(42)

        start = time.perf_counter()
        mutation.apply("test", mock_target, rng)
        elapsed = time.perf_counter() - start

        assert elapsed >= 0.1
        assert elapsed < 0.2  # Some tolerance

    def test_latency_mutation_calls_target(self, mock_target: MockTarget) -> None:
        """LatencyMutation MUST call target (passthrough behavior)."""
        import random

        mutation = LatencyMutation(delay_seconds=0.01)
        rng = random.Random(42)

        result = mutation.apply("Hello", mock_target, rng)

        assert mock_target.call_count == 1
        assert result == "Hello from target"

    def test_latency_mutation_implements_protocol(self) -> None:
        """LatencyMutation should satisfy Mutation protocol."""
        mutation = LatencyMutation()
        assert isinstance(mutation, Mutation)


# ============================================================================
# MUTATION TESTS - ERROR
# ============================================================================


class TestErrorMutation:
    """Tests for ErrorMutation."""

    def test_error_mutation_name(self) -> None:
        """Mutation name should be 'error'."""
        mutation = ErrorMutation()
        assert mutation.name == "error"

    def test_error_mutation_raises_chaos_error(self, mock_target: MockTarget) -> None:
        """ErrorMutation should raise ChaosError."""
        import random

        mutation = ErrorMutation()
        rng = random.Random(42)

        with pytest.raises(ChaosError):
            mutation.apply("test", mock_target, rng)

    def test_error_mutation_skips_target(self, mock_target: MockTarget) -> None:
        """ErrorMutation MUST NOT call target (skip to save tokens)."""
        import random

        mutation = ErrorMutation()
        rng = random.Random(42)

        try:
            mutation.apply("test", mock_target, rng)
        except ChaosError:
            pass

        assert mock_target.call_count == 0

    def test_error_mutation_uses_default_codes(self, mock_target: MockTarget) -> None:
        """Default error codes should be 500, 503, 429."""
        import random

        mutation = ErrorMutation()
        rng = random.Random(42)

        error_codes_seen = set()
        for seed in range(100):
            rng = random.Random(seed)
            try:
                mutation.apply("test", mock_target, rng)
            except ChaosError as e:
                error_codes_seen.add(e.error_code)

        assert 500 in error_codes_seen
        assert 503 in error_codes_seen
        assert 429 in error_codes_seen

    def test_error_mutation_custom_codes(self, mock_target: MockTarget) -> None:
        """Custom error codes should be used when provided."""
        import random

        mutation = ErrorMutation(error_codes=[418])
        rng = random.Random(42)

        with pytest.raises(ChaosError) as exc_info:
            mutation.apply("test", mock_target, rng)

        assert exc_info.value.error_code == 418

    def test_error_mutation_implements_protocol(self) -> None:
        """ErrorMutation should satisfy Mutation protocol."""
        mutation = ErrorMutation()
        assert isinstance(mutation, Mutation)


# ============================================================================
# MUTATION TESTS - JSON
# ============================================================================


class TestJsonMutation:
    """Tests for JsonMutation."""

    def test_json_mutation_name(self) -> None:
        """Mutation name should be 'json'."""
        mutation = JsonMutation()
        assert mutation.name == "json"

    def test_json_mutation_returns_corrupted(self, mock_target: MockTarget) -> None:
        """JsonMutation should return a corrupted payload."""
        import random

        mutation = JsonMutation()
        rng = random.Random(42)

        result = mutation.apply("test", mock_target, rng)

        assert result in JsonMutation.CORRUPTION_PAYLOADS

    def test_json_mutation_skips_target(self, mock_target: MockTarget) -> None:
        """JsonMutation MUST NOT call target (skip to save tokens)."""
        import random

        mutation = JsonMutation()
        rng = random.Random(42)

        mutation.apply("test", mock_target, rng)

        assert mock_target.call_count == 0

    def test_json_mutation_unclosed_object(self, mock_target: MockTarget) -> None:
        """Unclosed object payload should be one of the options."""
        assert '{"key": "value"' in JsonMutation.CORRUPTION_PAYLOADS

    def test_json_mutation_empty_baseline(self, mock_target: MockTarget) -> None:
        """Empty string should be one of the options."""
        assert "" in JsonMutation.CORRUPTION_PAYLOADS

    def test_json_mutation_wrong_type(self, mock_target: MockTarget) -> None:
        """Wrong type payload should be one of the options."""
        assert '{"count": "not_a_number"}' in JsonMutation.CORRUPTION_PAYLOADS

    def test_json_mutation_unclosed_array(self, mock_target: MockTarget) -> None:
        """Unclosed array payload should be one of the options."""
        assert "[1, 2," in JsonMutation.CORRUPTION_PAYLOADS

    def test_json_mutation_implements_protocol(self) -> None:
        """JsonMutation should satisfy Mutation protocol."""
        mutation = JsonMutation()
        assert isinstance(mutation, Mutation)


# ============================================================================
# CHAOS INJECTOR TESTS
# ============================================================================


class TestChaosInjector:
    """Tests for ChaosInjector."""

    def test_injector_wrap_returns_chaos_target(
        self, mock_target: MockTarget, basic_chaos_config: ChaosConfig
    ) -> None:
        """wrap() should return a ChaosTarget."""
        injector = ChaosInjector(basic_chaos_config)
        result = injector.wrap(mock_target)

        assert isinstance(result, ChaosTarget)

    def test_injector_respects_probability_0(self, mock_target: MockTarget) -> None:
        """probability=0.0 should never apply mutations."""
        config = ChaosConfig(
            probability=0.0,
            latency_enabled=True,
            errors_enabled=True,
            json_enabled=True,
        )
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        # Run 100 calls - none should have mutations
        for _ in range(100):
            result = chaos_target("test")
            assert result == "Hello from target"

        assert mock_target.call_count == 100

    def test_injector_respects_probability_1(self, mock_target: MockTarget) -> None:
        """probability=1.0 should always apply mutations."""
        config = ChaosConfig(
            probability=1.0,
            latency_enabled=False,  # Disable latency (it calls target)
            errors_enabled=False,
            json_enabled=True,  # Only json enabled (returns corrupted)
            random_seed=42,
        )
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        # Run 100 calls - all should have mutations
        for _ in range(100):
            result = chaos_target("test")
            assert result in JsonMutation.CORRUPTION_PAYLOADS

        # Target should never be called (json mutation skips)
        assert mock_target.call_count == 0

    def test_injector_with_seed_deterministic(self, mock_target: MockTarget) -> None:
        """Same seed should produce same mutation sequence."""
        config = ChaosConfig(
            probability=1.0,
            json_enabled=True,
            random_seed=12345,
        )

        # Run 1
        injector1 = ChaosInjector(config)
        target1 = injector1.wrap(mock_target)
        results1 = [target1("test") for _ in range(10)]

        # Run 2 (same seed)
        injector2 = ChaosInjector(config)
        target2 = injector2.wrap(mock_target)
        results2 = [target2("test") for _ in range(10)]

        assert results1 == results2

    def test_injector_selects_enabled_only(self, mock_target: MockTarget) -> None:
        """Only enabled mutations should be selected."""
        config = ChaosConfig(
            probability=1.0,
            latency_enabled=False,
            errors_enabled=False,
            json_enabled=True,  # Only JSON enabled
            random_seed=42,
        )
        injector = ChaosInjector(config)

        assert len(injector.mutations) == 1
        assert injector.mutations[0].name == "json"

    def test_injector_builds_all_mutations(
        self, basic_chaos_config: ChaosConfig
    ) -> None:
        """All enabled mutations should be in the list."""
        injector = ChaosInjector(basic_chaos_config)

        mutation_names = {m.name for m in injector.mutations}
        assert mutation_names == {"latency", "error", "json"}

    def test_injector_no_mutations_when_none_enabled(
        self, mock_target: MockTarget
    ) -> None:
        """With no mutations enabled, all calls go to target."""
        config = ChaosConfig(
            probability=1.0,
            latency_enabled=False,
            errors_enabled=False,
            json_enabled=False,
        )
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        for _ in range(10):
            result = chaos_target("test")
            assert result == "Hello from target"

        assert mock_target.call_count == 10


# ============================================================================
# CHAOS TARGET TESTS
# ============================================================================


class TestChaosTarget:
    """Tests for ChaosTarget."""

    def test_chaos_target_delegates_id(
        self, mock_target: MockTarget, basic_chaos_config: ChaosConfig
    ) -> None:
        """ChaosTarget.id should return wrapped target's id."""
        injector = ChaosInjector(basic_chaos_config)
        chaos_target = injector.wrap(mock_target)

        assert chaos_target.id == mock_target.id
        assert chaos_target.id == "t_mock123"

    def test_chaos_target_delegates_locator(
        self, mock_target: MockTarget, basic_chaos_config: ChaosConfig
    ) -> None:
        """ChaosTarget.locator should return wrapped target's locator."""
        injector = ChaosInjector(basic_chaos_config)
        chaos_target = injector.wrap(mock_target)

        assert chaos_target.locator == mock_target.locator
        assert chaos_target.locator == "mock_agent.py:mock_fn"

    def test_chaos_target_unwrapped(
        self, mock_target: MockTarget, basic_chaos_config: ChaosConfig
    ) -> None:
        """unwrapped property should return original target."""
        injector = ChaosInjector(basic_chaos_config)
        chaos_target = injector.wrap(mock_target)

        assert chaos_target.unwrapped is mock_target

    def test_chaos_target_implements_target_protocol(
        self, mock_target: MockTarget, basic_chaos_config: ChaosConfig
    ) -> None:
        """ChaosTarget should implement Target protocol."""
        injector = ChaosInjector(basic_chaos_config)
        chaos_target = injector.wrap(mock_target)

        assert isinstance(chaos_target, Target)

    def test_chaos_target_callable(
        self, mock_target: MockTarget, basic_chaos_config: ChaosConfig
    ) -> None:
        """ChaosTarget should be callable."""
        config = ChaosConfig(probability=0.0)  # No chaos
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        result = chaos_target("Hello")
        assert result == "Hello from target"

    def test_chaos_target_calls_target_when_no_chaos(
        self, mock_target: MockTarget
    ) -> None:
        """When probability is 0, target should be called normally."""
        config = ChaosConfig(probability=0.0)
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(mock_target)

        chaos_target("Hello")

        assert mock_target.call_count == 1
        assert mock_target._last_message == "Hello"


# ============================================================================
# LAW COMPLIANCE TESTS
# ============================================================================


class TestLawCompliance:
    """Tests for Law compliance."""

    def test_no_cli_imports(self) -> None:
        """Law 2: chaos.py should not import typer, rich, or click."""
        import inspect

        import serix_v2.services.chaos as chaos_module

        source = inspect.getsource(chaos_module)

        assert "from typer" not in source
        assert "import typer" not in source
        assert "from rich" not in source
        assert "import rich" not in source
        assert "from click" not in source
        assert "import click" not in source

    def test_chaos_config_is_pydantic(self) -> None:
        """Law 1: ChaosConfig should be Pydantic BaseModel."""
        from pydantic import BaseModel

        assert issubclass(ChaosConfig, BaseModel)

    def test_mutation_protocol_runtime_checkable(self) -> None:
        """Law 3: Mutation protocol should be runtime checkable."""
        assert isinstance(LatencyMutation(), Mutation)
        assert isinstance(ErrorMutation(), Mutation)
        assert isinstance(JsonMutation(), Mutation)
