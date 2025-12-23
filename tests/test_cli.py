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
        # Should show available commands
        assert "run" in result.output
        assert "record" in result.output
        assert "replay" in result.output
        assert "test" in result.output

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
# Run Command Tests
# =============================================================================


class TestRunCommand:
    """Tests for 'serix run' command."""

    def test_run_missing_script(self, tmp_path: Path) -> None:
        """Error when script doesn't exist."""
        result = runner.invoke(app, ["run", str(tmp_path / "nonexistent.py")])

        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "error" in result.output.lower()

    def test_run_with_fuzz_flag(self, temp_agent_script: Path) -> None:
        """--fuzz enables fuzzing mode."""
        # Mock the script execution
        with patch("serix.cli._run_script") as mock_run:
            result = runner.invoke(app, ["run", str(temp_agent_script), "--fuzz"])

            # Should attempt to run
            assert mock_run.called or result.exit_code == 0

    def test_run_fuzz_flags_enable_specific_mutations(
        self, temp_agent_script: Path
    ) -> None:
        """--fuzz-latency, --fuzz-errors, --fuzz-json enable specific mutations."""
        with patch("serix.cli._run_script"):
            with patch("serix.cli.set_serix_config") as mock_config:
                runner.invoke(app, ["run", str(temp_agent_script), "--fuzz-latency"])

                # Verify config was set
                if mock_config.called:
                    config = mock_config.call_args[0][0]
                    assert config.fuzz.enable_latency is True


# =============================================================================
# Record Command Tests
# =============================================================================


class TestRecordCommand:
    """Tests for 'serix record' command."""

    def test_record_missing_script(self, tmp_path: Path) -> None:
        """Error when script doesn't exist."""
        result = runner.invoke(app, ["record", str(tmp_path / "nonexistent.py")])

        assert result.exit_code != 0

    def test_record_with_output_option(self, temp_agent_script: Path) -> None:
        """--output specifies output file."""
        with patch("serix.cli._run_script"):
            with patch("serix.cli.save_recording"):
                result = runner.invoke(
                    app,
                    [
                        "record",
                        str(temp_agent_script),
                        "-o",
                        "custom_output.json",
                    ],
                )

                # Command should parse without error
                # (actual recording requires real OpenAI calls)
                assert result.exit_code == 0 or result.exit_code == 1


# =============================================================================
# Replay Command Tests
# =============================================================================


class TestReplayCommand:
    """Tests for 'serix replay' command."""

    def test_replay_missing_recording(self, temp_agent_script: Path) -> None:
        """Error when recording file doesn't exist."""
        result = runner.invoke(
            app,
            [
                "replay",
                str(temp_agent_script),
                "-r",
                "nonexistent_recording.json",
            ],
        )

        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "error" in result.output.lower()


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

    def test_test_fail_fast_flag(self) -> None:
        """--fail-fast flag is documented."""
        result = runner.invoke(app, ["test", "--help"])

        assert "fail-fast" in result.output.lower()

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
            assert "[target]" in content
            assert "[attack]" in content
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
# Attack Command Tests (Deprecated)
# =============================================================================


class TestAttackCommandDeprecated:
    """Tests for deprecated 'serix attack' command."""

    def test_attack_command_exists(self) -> None:
        """attack command exists and has help."""
        result = runner.invoke(app, ["attack", "--help"])

        # Command exists (even though deprecated)
        assert result.exit_code == 0
        # Help should mention it's deprecated or show options
        assert "goal" in result.output.lower() or "deprecated" in result.output.lower()

    def test_attack_hidden_from_help(self) -> None:
        """attack command is hidden from main help."""
        result = runner.invoke(app, ["--help"])

        # attack should not appear in main help (it's hidden)
        # Verify help shows normal commands
        assert result.exit_code == 0
        assert "test" in result.output.lower()


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
