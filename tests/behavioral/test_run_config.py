"""Behavioral contract tests for TestRunConfig.

These tests verify that TestRunConfig helper methods correctly
reflect flag values.
"""

from __future__ import annotations

from pathlib import Path

from serix.core.run_config import TestRunConfig


class TestShouldWriteToDisk:
    """Tests for should_write_to_disk() method."""

    def test_default_returns_true(self) -> None:
        """Default: disk writes are allowed."""
        config = TestRunConfig()
        assert config.should_write_to_disk() is True

    def test_dry_run_returns_false(self) -> None:
        """With dry_run=True: disk writes are blocked."""
        config = TestRunConfig(dry_run=True)
        assert config.should_write_to_disk() is False


class TestShouldRunSecurityTests:
    """Tests for should_run_security_tests() method."""

    def test_default_returns_true(self) -> None:
        """Default: security tests run."""
        config = TestRunConfig()
        assert config.should_run_security_tests() is True

    def test_fuzz_only_returns_false(self) -> None:
        """With fuzz_only=True: security tests skipped."""
        config = TestRunConfig(fuzz_only=True)
        assert config.should_run_security_tests() is False


class TestShouldGenerateReport:
    """Tests for should_generate_report() method."""

    def test_no_path_returns_false(self) -> None:
        """Without report_path: no report generated."""
        config = TestRunConfig(no_report=False, report_path=None)
        assert config.should_generate_report() is False

    def test_with_path_returns_true(self) -> None:
        """With report_path: report generated."""
        config = TestRunConfig(no_report=False, report_path=Path("report.html"))
        assert config.should_generate_report() is True

    def test_no_report_flag_returns_false(self) -> None:
        """With no_report=True: report skipped even with path."""
        config = TestRunConfig(no_report=True, report_path=Path("report.html"))
        assert config.should_generate_report() is False


class TestShouldGeneratePatches:
    """Tests for should_generate_patches() method."""

    def test_default_returns_true(self) -> None:
        """Default: patches are generated."""
        config = TestRunConfig()
        assert config.should_generate_patches() is True

    def test_no_patch_returns_false(self) -> None:
        """With no_patch=True: patches skipped."""
        config = TestRunConfig(no_patch=True)
        assert config.should_generate_patches() is False


class TestDefaultValues:
    """Tests for TestRunConfig default values."""

    def test_default_model_values(self) -> None:
        """Default model values are set correctly."""
        config = TestRunConfig()
        assert config.attacker_model == "gpt-4o-mini"
        assert config.judge_model == "gpt-4o"
        assert config.critic_model == "gpt-4o-mini"
        assert config.patcher_model == "gpt-4o"
        assert config.analyzer_model == "gpt-4o-mini"

    def test_default_behavior_flags(self) -> None:
        """Default behavior flags are False."""
        config = TestRunConfig()
        assert config.dry_run is False
        assert config.fuzz_only is False
        assert config.no_report is False
        assert config.no_patch is False
        assert config.exhaustive is False
        assert config.skip_regression is False

    def test_default_attack_config(self) -> None:
        """Default attack configuration values."""
        config = TestRunConfig()
        assert config.mode == "adaptive"
        assert config.depth == 3
        assert config.goals == []
        assert config.scenarios is None
