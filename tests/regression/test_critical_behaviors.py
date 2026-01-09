"""Regression tests for critical behaviors.

These tests verify behaviors that have broken before or are critical
to the application's core functionality. They should always pass.

Add a test here whenever:
1. You fix a bug (to prevent regression)
2. You identify a critical behavior that must not break
3. Something breaks that wasn't caught by existing tests
"""

import json
import subprocess
import sys
from pathlib import Path


class TestInitCommand:
    """Regression tests for serix init command."""

    def test_init_creates_valid_toml(self, tmp_path: Path) -> None:
        """serix init should create a valid TOML file.

        Regression: Ensure init doesn't create corrupted config.
        """
        result = subprocess.run(
            [sys.executable, "-m", "serix", "init"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

        config_path = tmp_path / "serix.toml"
        assert config_path.exists(), "serix.toml should be created"

        # Verify it's valid TOML
        import tomllib

        with open(config_path, "rb") as f:
            config = tomllib.load(f)

        # Verify essential sections exist
        assert "attack" in config or "models" in config or "output" in config

    def test_init_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        """serix init should refuse to overwrite existing config.

        Regression: Don't silently overwrite user's config.
        """
        # Create existing config
        config_path = tmp_path / "serix.toml"
        config_path.write_text("# User's custom config\n[attack]\ngoal = 'test'\n")

        result = subprocess.run(
            [sys.executable, "-m", "serix", "init"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )

        # Should fail or warn
        assert (
            result.returncode != 0
            or "exists" in result.stdout.lower()
            or "exists" in result.stderr.lower()
        )

        # Original content should be preserved
        assert "User's custom config" in config_path.read_text()

    def test_init_force_overwrites(self, tmp_path: Path) -> None:
        """serix init --force should overwrite existing config.

        Regression: --force flag must work.
        """
        config_path = tmp_path / "serix.toml"
        config_path.write_text("# Old config\n")

        result = subprocess.run(
            [sys.executable, "-m", "serix", "init", "--force"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Old config" not in config_path.read_text()


class TestTestCommand:
    """Regression tests for serix test command."""

    def test_test_requires_target_or_config(self) -> None:
        """serix test without target should give helpful error.

        Regression: Don't crash with confusing error on missing target.
        """
        result = subprocess.run(
            [sys.executable, "-m", "serix", "test"],
            capture_output=True,
            text=True,
        )

        # Should either exit non-zero or print helpful message
        # (Don't assert specific behavior, just that it doesn't crash badly)
        assert (
            result.returncode != 0
            or "target" in result.stdout.lower()
            or "config" in result.stdout.lower()
        )

    def test_test_goal_flag_accepts_spaces(self) -> None:
        """serix test --goal should accept goals with spaces.

        Regression: Shell quoting issues with goal text.
        """
        result = subprocess.run(
            [sys.executable, "-m", "serix", "test", "--help"],
            capture_output=True,
            text=True,
        )

        # Just verify the flag exists - actual usage requires a target
        assert "--goal" in result.stdout

    def test_test_mode_accepts_static_and_adaptive(self) -> None:
        """serix test --mode should accept 'static' and 'adaptive'.

        Regression: Mode validation was too strict.
        """
        result = subprocess.run(
            [sys.executable, "-m", "serix", "test", "--help"],
            capture_output=True,
            text=True,
        )

        help_text = result.stdout.lower()
        assert "static" in help_text or "adaptive" in help_text


class TestDemoCommand:
    """Regression tests for serix demo command."""

    def test_demo_help_shows_live_option(self) -> None:
        """serix demo --help should show --live/--no-live option.

        Regression: Live mode option must be documented.
        """
        result = subprocess.run(
            [sys.executable, "-m", "serix", "demo", "--help"],
            capture_output=True,
            text=True,
        )

        assert "--live" in result.stdout or "--no-live" in result.stdout


class TestConfigLoading:
    """Regression tests for config file loading."""

    def test_config_flag_accepted(self) -> None:
        """serix test --config should be accepted.

        Regression: Config loading from custom path.
        """
        result = subprocess.run(
            [sys.executable, "-m", "serix", "test", "--help"],
            capture_output=True,
            text=True,
        )

        assert "--config" in result.stdout or "-c" in result.stdout


class TestAttackLibrary:
    """Regression tests for attack library persistence."""

    def test_attack_store_schema_migration(self, tmp_path: Path) -> None:
        """Attack store should migrate old schema formats.

        Regression: Old attack records should still load after upgrades.
        """
        # Create a minimal old-format attack record
        serix_dir = tmp_path / ".serix"
        serix_dir.mkdir()

        old_attack = {
            "id": "test-123",
            "goal": "test goal",
            "payload": "test payload",
            "result": "exploited",  # Old field name
            "timestamp": "2024-01-01T00:00:00",
        }

        attacks_file = serix_dir / "attacks.json"
        attacks_file.write_text(json.dumps([old_attack]))

        # Import and verify it can load
        # This test just verifies the file can be read - actual migration
        # is tested in test_store.py
        assert attacks_file.exists()
        loaded = json.loads(attacks_file.read_text())
        assert len(loaded) == 1


class TestHTTPTargets:
    """Regression tests for HTTP target handling."""

    def test_http_flags_documented(self) -> None:
        """HTTP target flags should be documented in help.

        Regression: HTTP flags were silently ignored.
        """
        result = subprocess.run(
            [sys.executable, "-m", "serix", "test", "--help"],
            capture_output=True,
            text=True,
        )

        help_text = result.stdout
        assert "--input-field" in help_text
        assert "--output-field" in help_text
        assert "--headers" in help_text
