"""
Tests for FuzzService.

Phase 6: Fuzz/Resilience Testing
Reference: PHASE-6-FUZZ-2025-12-30.md
"""

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import ResilienceResult
from serix_v2.services.fuzz import FuzzService
from tests.serix_v2.mocks import MockCrashingTarget, MockHTTPErrorTarget, MockTarget


def _make_config(
    fuzz: bool = False,
    fuzz_latency: float | None = None,
    fuzz_errors: bool = False,
    fuzz_json: bool = False,
) -> SerixSessionConfig:
    """Helper to create a config with fuzz settings."""
    return SerixSessionConfig(
        target_path="test.py:fn",
        fuzz=fuzz,
        fuzz_latency=fuzz_latency,
        fuzz_errors=fuzz_errors,
        fuzz_json=fuzz_json,
    )


class TestFuzzServiceFlagLogic:
    """Tests for flag-to-logic mapping (Law 5)."""

    def test_no_tests_when_fuzz_disabled(self) -> None:
        """No tests run when all fuzz flags are False."""
        config = _make_config(
            fuzz=False,
            fuzz_latency=None,
            fuzz_errors=False,
            fuzz_json=False,
        )
        target = MockTarget()

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 0

    def test_all_tests_when_fuzz_enabled(self) -> None:
        """All 5 tests run when --fuzz is set."""
        config = _make_config(fuzz=True)
        target = MockTarget()

        service = FuzzService(target=target, config=config)
        results = service.run()

        # Should have: latency + 3 errors + json_corruption = 5
        assert len(results) == 5
        test_types = {r.test_type for r in results}
        assert test_types == {
            "latency",
            "http_500",
            "http_503",
            "http_429",
            "json_corruption",
        }

    def test_only_latency_when_fuzz_latency_set(self) -> None:
        """Only latency test when --fuzz-latency specified."""
        config = _make_config(fuzz_latency=0.01)  # Very short for fast test
        target = MockTarget()

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 1
        assert results[0].test_type == "latency"

    def test_only_errors_when_fuzz_errors_set(self) -> None:
        """Only error tests when --fuzz-errors specified."""
        config = _make_config(fuzz_errors=True)
        target = MockTarget()

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 3
        test_types = {r.test_type for r in results}
        assert test_types == {"http_500", "http_503", "http_429"}

    def test_only_json_when_fuzz_json_set(self) -> None:
        """Only JSON corruption test when --fuzz-json specified."""
        config = _make_config(fuzz_json=True)
        target = MockTarget()

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 1
        assert results[0].test_type == "json_corruption"


class TestFuzzServiceLatency:
    """Tests for latency resilience."""

    def test_latency_passes_on_healthy_target(self) -> None:
        """Latency test passes when target handles delay gracefully."""
        config = _make_config(fuzz_latency=0.01)  # Short delay for fast test
        target = MockTarget(responses=["OK"])

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].test_type == "latency"
        assert "gracefully" in results[0].details

    def test_latency_fails_on_crashing_target(self) -> None:
        """Latency test fails when target crashes."""
        config = _make_config(fuzz_latency=0.01)
        target = MockCrashingTarget(crash_on_calls=[0])

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 1
        assert results[0].passed is False
        assert "crashed" in results[0].details.lower()


class TestFuzzServiceErrors:
    """Tests for error resilience."""

    def test_errors_pass_on_healthy_target(self) -> None:
        """Error tests pass when target handles errors gracefully."""
        config = _make_config(fuzz_errors=True)
        target = MockTarget()

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 3
        for result in results:
            assert result.passed is True

    def test_errors_fail_on_http_error_target(self) -> None:
        """Error tests fail when target raises HTTP errors."""
        config = _make_config(fuzz_errors=True)
        target = MockHTTPErrorTarget(error_code=500)

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 3
        for result in results:
            assert result.passed is False
            assert "crashed" in result.details.lower()


class TestFuzzServiceJsonCorruption:
    """Tests for JSON corruption resilience."""

    def test_json_corruption_passes_on_healthy_target(self) -> None:
        """JSON corruption test passes when target handles bad input."""
        config = _make_config(fuzz_json=True)
        target = MockTarget(responses=["OK"])

        service = FuzzService(target=target, config=config)
        results = service.run()

        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].test_type == "json_corruption"


class TestFuzzServiceLawCompliance:
    """Tests for Law compliance."""

    def test_returns_resilience_result_models(self) -> None:
        """Law 1 compliance: Returns Pydantic models, not dicts."""
        config = _make_config(fuzz=True)
        target = MockTarget()

        service = FuzzService(target=target, config=config)
        results = service.run()

        for result in results:
            assert isinstance(result, ResilienceResult)

    def test_uses_effective_fuzz_latency(self) -> None:
        """Uses config's get_effective_fuzz_latency() for delay."""
        # When fuzz_latency is None but fuzz=True, should use default
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz=True,
            fuzz_latency=None,  # Will use DEFAULT_FUZZ_LATENCY
        )

        # get_effective_fuzz_latency() returns DEFAULT_FUZZ_LATENCY (5.0)
        assert config.get_effective_fuzz_latency() == 5.0
