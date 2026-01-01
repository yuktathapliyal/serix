"""CLI flag verification tests.

These tests verify that documented CLI flags exist in the actual CLI.
When adding a new flag:
1. Add a test for it here FIRST (it will fail)
2. Implement the flag
3. Test passes

This enforces test-first development for CLI changes.
"""

import subprocess
import sys

import pytest


def get_command_help(command: str) -> str:
    """Get the --help output for a serix command."""
    result = subprocess.run(
        [sys.executable, "-m", "serix", command, "--help"],
        capture_output=True,
        text=True,
    )
    return result.stdout


class TestTestCommandFlags:
    """Test that serix test has all documented flags."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Get help output once for all tests."""
        self.help_text = get_command_help("test")

    # ═══════════════════════════════════════════════════════════════════════
    # CORE FLAGS (v0.2.x - must exist)
    # ═══════════════════════════════════════════════════════════════════════

    def test_has_mode_flag(self) -> None:
        """--mode flag for attack mode selection."""
        assert "--mode" in self.help_text

    def test_has_goal_flag(self) -> None:
        """--goal flag for attack objective."""
        assert "--goal" in self.help_text

    def test_has_goals_flag(self) -> None:
        """--goals flag for comma-separated goals."""
        assert "--goals" in self.help_text

    def test_has_goals_file_flag(self) -> None:
        """--goals-file flag for loading goals from file."""
        assert "--goals-file" in self.help_text

    def test_has_scenarios_flag(self) -> None:
        """--scenarios flag for persona selection."""
        assert "--scenarios" in self.help_text

    def test_has_depth_flag(self) -> None:
        """--depth flag for attack depth."""
        assert "--depth" in self.help_text

    def test_has_report_flag(self) -> None:
        """--report flag for HTML report generation."""
        assert "--report" in self.help_text

    # NOTE: --json-report removed in v0.3.0 (JSON auto-saved to .serix/)

    def test_has_github_flag(self) -> None:
        """--github flag for CI/CD integration."""
        assert "--github" in self.help_text

    def test_has_live_flag(self) -> None:
        """--live flag for live UI mode."""
        assert "--live" in self.help_text

    def test_has_verbose_flag(self) -> None:
        """--verbose/-v flag for verbose output."""
        assert "--verbose" in self.help_text or "-v" in self.help_text

    def test_has_config_flag(self) -> None:
        """--config/-c flag for config file path."""
        assert "--config" in self.help_text

    # ═══════════════════════════════════════════════════════════════════════
    # MODEL FLAGS (v0.2.x - must exist)
    # ═══════════════════════════════════════════════════════════════════════

    def test_has_judge_model_flag(self) -> None:
        """--judge-model flag for judge model selection."""
        assert "--judge-model" in self.help_text

    # ═══════════════════════════════════════════════════════════════════════
    # HTTP TARGET FLAGS (v0.2.x - must exist)
    # ═══════════════════════════════════════════════════════════════════════

    def test_has_input_field_flag(self) -> None:
        """--input-field flag for HTTP request field."""
        assert "--input-field" in self.help_text

    def test_has_output_field_flag(self) -> None:
        """--output-field flag for HTTP response field."""
        assert "--output-field" in self.help_text

    def test_has_headers_flag(self) -> None:
        """--headers flag for HTTP headers."""
        assert "--headers" in self.help_text

    # ═══════════════════════════════════════════════════════════════════════
    # ATTACK LIBRARY FLAGS (v0.3.0 - deprecated flags removed)
    # ═══════════════════════════════════════════════════════════════════════

    # NOTE: --no-save, --save-all, --fail-fast removed in v0.3.0
    # See docs/specs/09-feature-inventory-2025-12-28.md

    def test_has_skip_mitigated_flag(self) -> None:
        """--skip-mitigated flag for immune check."""
        assert "--skip-mitigated" in self.help_text

    # ═══════════════════════════════════════════════════════════════════════
    # FUZZ FLAGS (v0.2.x - must exist)
    # ═══════════════════════════════════════════════════════════════════════

    def test_has_fuzz_flag(self) -> None:
        """--fuzz flag for enabling fuzzing."""
        assert "--fuzz" in self.help_text

    def test_has_fuzz_latency_flag(self) -> None:
        """--fuzz-latency flag for latency injection."""
        assert "--fuzz-latency" in self.help_text

    def test_has_fuzz_errors_flag(self) -> None:
        """--fuzz-errors flag for error injection."""
        assert "--fuzz-errors" in self.help_text

    def test_has_fuzz_json_flag(self) -> None:
        """--fuzz-json flag for JSON corruption."""
        assert "--fuzz-json" in self.help_text

    def test_has_fuzz_probability_flag(self) -> None:
        """--fuzz-probability flag for mutation probability."""
        assert "--fuzz-probability" in self.help_text

    # ═══════════════════════════════════════════════════════════════════════
    # v0.3.0 FLAGS (to be implemented - currently expected to FAIL)
    # Uncomment these as you implement each flag
    # ═══════════════════════════════════════════════════════════════════════

    def test_has_attacker_model_flag(self) -> None:
        """--attacker-model flag for attack model selection."""
        assert "--attacker-model" in self.help_text

    def test_has_critic_model_flag(self) -> None:
        """--critic-model flag for critic model selection."""
        assert "--critic-model" in self.help_text

    def test_has_skip_regression_flag(self) -> None:
        """--skip-regression flag to skip immune check."""
        assert "--skip-regression" in self.help_text

    def test_has_exhaustive_flag(self) -> None:
        """--exhaustive flag to continue after first exploit."""
        assert "--exhaustive" in self.help_text

    def test_has_name_flag(self) -> None:
        """--name flag for target alias."""
        assert "--name" in self.help_text

    def test_has_target_id_flag(self) -> None:
        """--target-id flag for explicit target ID."""
        assert "--target-id" in self.help_text


class TestDemoCommandFlags:
    """Test that serix demo has all documented flags."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Get help output once for all tests."""
        self.help_text = get_command_help("demo")

    def test_has_live_flag(self) -> None:
        """--live/--no-live flag for UI mode."""
        assert "--live" in self.help_text or "--no-live" in self.help_text

    def test_has_report_flag(self) -> None:
        """--report flag for HTML report."""
        assert "--report" in self.help_text

    def test_has_verbose_flag(self) -> None:
        """--verbose flag for verbose output."""
        assert "--verbose" in self.help_text

    def test_has_force_flag(self) -> None:
        """--force flag to continue on regression check failure."""
        assert "--force" in self.help_text


class TestRunCommandFlags:
    """Test that serix run has all documented flags."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Get help output once for all tests."""
        self.help_text = get_command_help("run")

    def test_has_fuzz_flag(self) -> None:
        """--fuzz flag for enabling fuzzing."""
        assert "--fuzz" in self.help_text

    def test_has_verbose_flag(self) -> None:
        """--verbose flag for verbose output."""
        assert "--verbose" in self.help_text


class TestRecordCommandFlags:
    """Test that serix record has all documented flags."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Get help output once for all tests."""
        self.help_text = get_command_help("record")

    def test_has_output_flag(self) -> None:
        """--output flag for recording output path."""
        assert "--output" in self.help_text or "-o" in self.help_text


class TestReplayCommandFlags:
    """Test that serix replay has all documented flags."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Get help output once for all tests."""
        self.help_text = get_command_help("replay")

    def test_has_recording_flag(self) -> None:
        """--recording flag for replay input path."""
        assert "--recording" in self.help_text or "-r" in self.help_text


class TestInitCommandFlags:
    """Test that serix init has all documented flags."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Get help output once for all tests."""
        self.help_text = get_command_help("init")

    def test_has_force_flag(self) -> None:
        """--force/-f flag for overwriting existing config."""
        assert "--force" in self.help_text or "-f" in self.help_text


# ═══════════════════════════════════════════════════════════════════════════
# v0.3.0 STATUS COMMAND (to be implemented)
# Uncomment when implementing serix status
# ═══════════════════════════════════════════════════════════════════════════

# class TestStatusCommandFlags:
#     """Test that serix status has all documented flags."""
#
#     @pytest.fixture(autouse=True)
#     def setup(self) -> None:
#         """Get help output once for all tests."""
#         self.help_text = get_command_help("status")
#
#     def test_has_name_flag(self) -> None:
#         """--name flag for filtering by target alias."""
#         assert "--name" in self.help_text
#
#     def test_has_target_id_flag(self) -> None:
#         """--target-id flag for filtering by ID."""
#         assert "--target-id" in self.help_text
#
#     def test_has_json_flag(self) -> None:
#         """--json flag for JSON output."""
#         assert "--json" in self.help_text
#
#     def test_has_verbose_flag(self) -> None:
#         """--verbose flag for per-attack details."""
#         assert "--verbose" in self.help_text
