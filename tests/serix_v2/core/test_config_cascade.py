"""
Serix v2 - Configuration Cascade Tests

Phase 7.2: 15 tests for SerixSessionConfig helper methods.

These tests verify that configuration flags properly map to behavior
via the helper methods defined in SerixSessionConfig.

Reference: docs/serix-phoenix-rebuild/build-plans/PHASE-7-COMPREHENSIVE-TESTS-2025-12-30.md
"""

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.constants import DEFAULT_FUZZ_LATENCY


class TestSerixSessionConfigHelpers:
    """Tests for SerixSessionConfig helper methods (Law 5 compliance)."""

    # =========================================================================
    # should_write_to_disk()
    # =========================================================================

    def test_should_write_to_disk_false_when_dry_run(self) -> None:
        """dry_run=True prevents disk writes."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            dry_run=True,
        )
        assert config.should_write_to_disk() is False

    def test_should_write_to_disk_true_when_not_dry_run(self) -> None:
        """dry_run=False (default) allows disk writes."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            dry_run=False,
        )
        assert config.should_write_to_disk() is True

    # =========================================================================
    # should_run_security_tests()
    # =========================================================================

    def test_should_run_security_tests_false_when_fuzz_only(self) -> None:
        """fuzz_only=True skips security tests."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz_only=True,
        )
        assert config.should_run_security_tests() is False

    def test_should_run_security_tests_true_by_default(self) -> None:
        """Security tests run by default."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
        )
        assert config.should_run_security_tests() is True

    # =========================================================================
    # should_run_regression()
    # =========================================================================

    def test_should_run_regression_false_when_skip_regression(self) -> None:
        """skip_regression=True skips regression phase."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            skip_regression=True,
        )
        assert config.should_run_regression() is False

    def test_should_run_regression_false_when_fuzz_only(self) -> None:
        """fuzz_only=True also skips regression (no security tests)."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz_only=True,
        )
        assert config.should_run_regression() is False

    def test_should_run_regression_true_by_default(self) -> None:
        """Regression runs by default."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
        )
        assert config.should_run_regression() is True

    # =========================================================================
    # should_run_fuzz_tests()
    # =========================================================================

    def test_should_run_fuzz_tests_true_when_fuzz(self) -> None:
        """fuzz=True enables fuzz tests."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz=True,
        )
        assert config.should_run_fuzz_tests() is True

    def test_should_run_fuzz_tests_true_when_fuzz_latency(self) -> None:
        """fuzz_latency=N enables fuzz tests."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz_latency=1.0,
        )
        assert config.should_run_fuzz_tests() is True

    def test_should_run_fuzz_tests_true_when_fuzz_only(self) -> None:
        """fuzz_only=True enables fuzz tests."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz_only=True,
        )
        assert config.should_run_fuzz_tests() is True

    def test_should_run_fuzz_tests_false_by_default(self) -> None:
        """Fuzz tests don't run by default."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
        )
        assert config.should_run_fuzz_tests() is False

    # =========================================================================
    # should_generate_report()
    # =========================================================================

    def test_should_generate_report_false_when_no_report(self) -> None:
        """no_report=True skips report generation."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            no_report=True,
        )
        assert config.should_generate_report() is False

    def test_should_generate_report_false_when_dry_run(self) -> None:
        """dry_run=True also skips report (no disk writes)."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            dry_run=True,
        )
        assert config.should_generate_report() is False

    # =========================================================================
    # should_generate_patch()
    # =========================================================================

    def test_should_generate_patch_false_when_no_patch(self) -> None:
        """no_patch=True skips patch generation."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            no_patch=True,
            system_prompt="test prompt",
        )
        assert config.should_generate_patch() is False

    def test_should_generate_patch_true_when_no_system_prompt(self) -> None:
        """No system_prompt still allows recommendations-only patches."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            no_patch=False,
            system_prompt=None,
        )
        # Patcher generates architectural recommendations even without system_prompt
        assert config.should_generate_patch() is True

    def test_should_generate_patch_true_when_enabled_with_prompt(self) -> None:
        """Patch generation requires both no_patch=False and system_prompt."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            no_patch=False,
            system_prompt="You are a helpful assistant.",
        )
        assert config.should_generate_patch() is True

    # =========================================================================
    # get_effective_fuzz_latency()
    # =========================================================================

    def test_get_effective_fuzz_latency_returns_explicit_value(self) -> None:
        """Explicit fuzz_latency value is returned."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz_latency=2.5,
        )
        assert config.get_effective_fuzz_latency() == 2.5

    def test_get_effective_fuzz_latency_returns_default(self) -> None:
        """Default fuzz latency is returned when not set."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz_latency=None,
        )
        assert config.get_effective_fuzz_latency() == DEFAULT_FUZZ_LATENCY

    # =========================================================================
    # is_interactive()
    # =========================================================================

    def test_is_interactive_false_when_yes_flag(self) -> None:
        """--yes flag disables interactive mode."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            yes=True,
        )
        assert config.is_interactive() is False

    def test_is_interactive_false_when_github_flag(self) -> None:
        """--github flag disables interactive mode."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            github=True,
        )
        assert config.is_interactive() is False

    def test_is_interactive_true_by_default(self) -> None:
        """Interactive mode is on by default."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
        )
        assert config.is_interactive() is True


class TestSerixSessionConfigCombinations:
    """Tests for flag combinations and edge cases."""

    def test_fuzz_errors_enables_fuzz_tests(self) -> None:
        """fuzz_errors=True enables fuzz tests."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz_errors=True,
        )
        assert config.should_run_fuzz_tests() is True

    def test_fuzz_json_enables_fuzz_tests(self) -> None:
        """fuzz_json=True enables fuzz tests."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz_json=True,
        )
        assert config.should_run_fuzz_tests() is True

    def test_multiple_fuzz_flags_all_enable(self) -> None:
        """Multiple fuzz flags all enable fuzz tests."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            fuzz=True,
            fuzz_latency=1.0,
            fuzz_errors=True,
            fuzz_json=True,
        )
        assert config.should_run_fuzz_tests() is True

    def test_dry_run_overrides_report_setting(self) -> None:
        """dry_run=True prevents report even if no_report=False."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            dry_run=True,
            no_report=False,  # Explicitly want report
        )
        # But dry_run prevents all disk writes
        assert config.should_generate_report() is False
        assert config.should_write_to_disk() is False
