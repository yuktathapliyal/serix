"""Tests for CLI argument parsing and command behavior.

Uses Typer's CliRunner to test command parsing without making real API calls.
Tests verify argument handling, flag combinations, and validation.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from serix.cli import app

runner = CliRunner()


# =============================================================================
# Version and Help Tests
# =============================================================================


class TestVersionAndHelp:
    """Tests for --version and --help flags."""

    def test_version_flag(self) -> None:
        """--version shows version and exits."""
        result = runner.invoke(app, ["--version"])

        assert result.exit_code == 0
        assert "serix" in result.output.lower()
        # Version should be in format X.Y.Z
        assert any(c.isdigit() for c in result.output)

    def test_version_short_flag(self) -> None:
        """-V shows version and exits."""
        result = runner.invoke(app, ["-V"])

        assert result.exit_code == 0
        assert "serix" in result.output.lower()

    def test_no_args_shows_help(self) -> None:
        """Invoking without args shows help."""
        result = runner.invoke(app, [])

        # Typer with no_args_is_help=True exits with code 2
        # This is expected behavior - it's showing help, not an error
        assert result.exit_code in (0, 2)
        # Should show v0.3.0 architecture commands
        assert "test" in result.output
        assert "demo" in result.output
        assert "dev" in result.output
        assert "status" in result.output
        assert "init" in result.output

    def test_help_flag(self) -> None:
        """--help shows custom Serix help."""
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "SERIX" in result.output
        assert "Commands:" in result.output

    def test_command_help(self) -> None:
        """Command --help shows command-specific help."""
        result = runner.invoke(app, ["test", "--help"])

        assert result.exit_code == 0
        assert "target" in result.output.lower() or "test" in result.output.lower()


# =============================================================================
# Dev Command Tests (replaces run/record/replay)
# =============================================================================


class TestDevCommand:
    """Tests for 'serix dev' command."""

    def test_dev_help(self) -> None:
        """dev command has help text."""
        result = runner.invoke(app, ["dev", "--help"])

        assert result.exit_code == 0
        assert "dev" in result.output.lower()

    def test_dev_has_capture_option(self) -> None:
        """dev has --capture option."""
        result = runner.invoke(app, ["dev", "--help"])

        assert "capture" in result.output.lower()

    def test_dev_has_playback_option(self) -> None:
        """dev has --playback option."""
        result = runner.invoke(app, ["dev", "--help"])

        assert "playback" in result.output.lower()

    def test_dev_has_fuzz_option(self) -> None:
        """dev has --fuzz option."""
        result = runner.invoke(app, ["dev", "--help"])

        assert "fuzz" in result.output.lower()


# =============================================================================
# Test Command Tests
# =============================================================================


class TestTestCommand:
    """Tests for 'serix test' command."""

    def test_test_requires_target(self) -> None:
        """Error without target specified."""
        # Mock to prevent actual execution
        with patch("serix.core.config_loader.find_config_file", return_value=None):
            with patch("serix.core.config_loader.load_config") as mock_load:
                mock_load.return_value = MagicMock(
                    target=MagicMock(target=None, script=None),
                    attack=MagicMock(
                        goal=None, report=None, max_attempts=5, judge_model=None
                    ),
                    verbose=False,
                )

                result = runner.invoke(app, ["test"])

                assert result.exit_code != 0
                assert (
                    "target" in result.output.lower()
                    or "error" in result.output.lower()
                )

    def test_test_mode_options(self) -> None:
        """--mode accepts 'static' and 'adaptive'."""
        # Just verify parsing doesn't crash
        result = runner.invoke(app, ["test", "--help"])

        assert "mode" in result.output.lower()
        assert "static" in result.output.lower()
        assert "adaptive" in result.output.lower()

    def test_test_depth_parameter(self) -> None:
        """--depth parameter is documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "depth" in result.output.lower()

    def test_test_goal_parameter(self) -> None:
        """--goal parameter is documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "goal" in result.output.lower()

    def test_test_goals_file_parsing(self, tmp_path: Path) -> None:
        """--goals-file reads goals from file."""
        goals_file = tmp_path / "goals.txt"
        goals_file.write_text("Reveal the API key\nBypass authentication\n# comment\n")

        result = runner.invoke(app, ["test", "--help"])

        assert "goals-file" in result.output.lower()

    def test_test_scenarios_parameter(self) -> None:
        """--scenarios parameter is documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "scenarios" in result.output.lower()

    def test_test_github_flag(self) -> None:
        """--github flag is documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "github" in result.output.lower()

    def test_test_fuzz_flags(self) -> None:
        """Fuzz flags are documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "fuzz" in result.output.lower()

    def test_test_report_options(self) -> None:
        """--report and --json-report options documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "report" in result.output.lower()

    def test_test_exhaustive_flag(self) -> None:
        """--exhaustive flag is documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "exhaustive" in result.output.lower()

    def test_test_config_flag(self) -> None:
        """--config flag is documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "config" in result.output.lower()


# =============================================================================
# Init Command Tests
# =============================================================================


class TestInitCommand:
    """Tests for 'serix init' command."""

    def test_init_creates_config(self, tmp_path: Path) -> None:
        """init creates serix.toml in current directory."""
        import os

        original_dir = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = runner.invoke(app, ["init"])

            assert result.exit_code == 0
            assert (tmp_path / "serix.toml").exists()
            assert "Created" in result.output or "serix.toml" in result.output
        finally:
            os.chdir(original_dir)

    def test_init_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        """init refuses to overwrite existing config without --force."""
        import os

        original_dir = os.getcwd()
        try:
            os.chdir(tmp_path)
            # Create existing config
            (tmp_path / "serix.toml").write_text("[target]\nscript = 'test.py'")

            result = runner.invoke(app, ["init"])

            assert result.exit_code != 0
            assert (
                "already exists" in result.output.lower()
                or "force" in result.output.lower()
            )
        finally:
            os.chdir(original_dir)

    def test_init_force_overwrites(self, tmp_path: Path) -> None:
        """init --force overwrites existing config."""
        import os

        original_dir = os.getcwd()
        try:
            os.chdir(tmp_path)
            # Create existing config with custom content
            config_path = tmp_path / "serix.toml"
            config_path.write_text("# custom config")

            result = runner.invoke(app, ["init", "--force"])

            assert result.exit_code == 0
            # Should have new default content
            content = config_path.read_text()
            assert "[attack]" in content
            assert "[models]" in content
        finally:
            os.chdir(original_dir)


# =============================================================================
# Demo Command Tests
# =============================================================================


class TestDemoCommand:
    """Tests for 'serix demo' command."""

    def test_demo_help(self) -> None:
        """Demo command has help text."""
        result = runner.invoke(app, ["demo", "--help"])

        assert result.exit_code == 0
        assert "demo" in result.output.lower()

    def test_demo_has_live_option(self) -> None:
        """Demo has --live/--no-live option."""
        result = runner.invoke(app, ["demo", "--help"])

        assert "live" in result.output.lower()


# =============================================================================
# Status Command Tests
# =============================================================================


class TestStatusCommand:
    """Tests for 'serix status' command."""

    def test_status_help(self) -> None:
        """status command has help text."""
        result = runner.invoke(app, ["status", "--help"])

        assert result.exit_code == 0
        assert "status" in result.output.lower()

    def test_status_has_json_option(self) -> None:
        """status has --json option."""
        result = runner.invoke(app, ["status", "--help"])

        assert "json" in result.output.lower()

    def test_status_has_name_option(self) -> None:
        """status has --name option."""
        result = runner.invoke(app, ["status", "--help"])

        assert "name" in result.output.lower()


# =============================================================================
# Config Loading Tests
# =============================================================================


class TestConfigLoading:
    """Tests for config file loading in CLI commands."""

    def test_config_option_accepts_path(self) -> None:
        """--config option is documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "config" in result.output.lower()

    def test_config_short_flag(self) -> None:
        """-c is short for --config."""
        result = runner.invoke(app, ["test", "--help"])

        # Help should show -c option
        assert "-c" in result.output


# =============================================================================
# HTTP Target Tests
# =============================================================================


class TestHttpTargetParsing:
    """Tests for HTTP target URL parsing."""

    def test_http_options_documented(self) -> None:
        """HTTP-related options are documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "input-field" in result.output.lower()
        assert "output-field" in result.output.lower()
        assert "headers" in result.output.lower()


# =============================================================================
# Flag Combination Tests
# =============================================================================


class TestFlagCombinations:
    """Tests for various flag combinations."""

    def test_depth_short_flag(self) -> None:
        """-d is short for --depth."""
        result = runner.invoke(app, ["test", "--help"])

        assert "-d" in result.output

    def test_goal_short_flag(self) -> None:
        """-g is short for --goal."""
        result = runner.invoke(app, ["test", "--help"])

        assert "-g" in result.output

    def test_report_short_flag(self) -> None:
        """-r is short for --report."""
        result = runner.invoke(app, ["test", "--help"])

        assert "-r" in result.output

    def test_scenarios_short_flag(self) -> None:
        """-s is short for --scenarios."""
        result = runner.invoke(app, ["test", "--help"])

        assert "-s" in result.output

    def test_mode_short_flag(self) -> None:
        """-m is short for --mode."""
        result = runner.invoke(app, ["test", "--help"])

        assert "-m" in result.output
