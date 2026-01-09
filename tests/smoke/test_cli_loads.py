"""Smoke tests for CLI loading.

These tests verify that the CLI loads without import errors and that
all commands are accessible. They should run in < 2 seconds.

If these fail, something is catastrophically broken.
"""

import subprocess
import sys

import pytest


class TestCLILoads:
    """Test that the CLI loads and basic commands work."""

    def test_version_flag_works(self) -> None:
        """serix --version should print version and exit 0."""
        result = subprocess.run(
            [sys.executable, "-m", "serix", "--version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "serix" in result.stdout.lower() or "0." in result.stdout

    def test_help_flag_works(self) -> None:
        """serix --help should print help and exit 0."""
        result = subprocess.run(
            [sys.executable, "-m", "serix", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Usage" in result.stdout or "usage" in result.stdout

    @pytest.mark.parametrize("command", ["test", "demo", "run", "init"])
    def test_command_help_works(self, command: str) -> None:
        """Each command's --help should work."""
        result = subprocess.run(
            [sys.executable, "-m", "serix", command, "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"'{command} --help' failed: {result.stderr}"
        assert "Usage" in result.stdout or "usage" in result.stdout


class TestCLIImports:
    """Test that CLI modules import without errors."""

    def test_main_module_imports(self) -> None:
        """serix module should import without errors."""
        import serix  # noqa: F401

    def test_cli_module_imports(self) -> None:
        """serix.cli module should import without errors."""
        import serix.cli  # noqa: F401

    def test_core_types_import(self) -> None:
        """serix.core.types module should import without errors."""
        from serix.core import types  # noqa: F401


class TestCriticalCommands:
    """Test that critical commands exist and have expected flags."""

    def test_test_command_has_goal_flag(self) -> None:
        """serix test should have --goal flag."""
        result = subprocess.run(
            [sys.executable, "-m", "serix", "test", "--help"],
            capture_output=True,
            text=True,
        )
        assert "--goal" in result.stdout

    def test_test_command_has_mode_flag(self) -> None:
        """serix test should have --mode flag."""
        result = subprocess.run(
            [sys.executable, "-m", "serix", "test", "--help"],
            capture_output=True,
            text=True,
        )
        assert "--mode" in result.stdout

    def test_demo_command_has_no_live_flag(self) -> None:
        """serix demo should have --no-live flag."""
        result = subprocess.run(
            [sys.executable, "-m", "serix", "demo", "--help"],
            capture_output=True,
            text=True,
        )
        assert "--no-live" in result.stdout or "--live" in result.stdout

    def test_init_command_has_force_flag(self) -> None:
        """serix init should have --force flag."""
        result = subprocess.run(
            [sys.executable, "-m", "serix", "init", "--help"],
            capture_output=True,
            text=True,
        )
        assert "--force" in result.stdout
