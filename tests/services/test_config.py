"""Tests for ConfigService."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from serix.services.config import ConfigService


class TestConfigDefaults:
    """Tests for default configuration."""

    def test_load_returns_defaults(self) -> None:
        """Test that load returns defaults when no config files exist."""
        config = ConfigService().load()

        assert config.attack.depth == 5
        assert config.attack.mode == "adaptive"
        assert config.models.judge == "gpt-4o"
        assert config.models.attacker == "gpt-4o-mini"
        assert config.verbose is False

    def test_defaults_have_correct_structure(self) -> None:
        """Test that defaults have all expected fields."""
        config = ConfigService().load()

        # Check all sections exist
        assert config.target is not None
        assert config.attack is not None
        assert config.regression is not None
        assert config.output is not None
        assert config.models is not None
        assert config.fuzz is not None


class TestConfigFileLoading:
    """Tests for loading configuration from files."""

    def test_load_from_serix_toml(self, tmp_path: Path) -> None:
        """Test loading from serix.toml."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text(
            """
[attack]
depth = 10
mode = "static"

[models]
judge = "gpt-4o-mini"
"""
        )

        # Change to temp dir
        original_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            config = ConfigService().load()
            assert config.attack.depth == 10
            assert config.attack.mode == "static"
            assert config.models.judge == "gpt-4o-mini"
        finally:
            os.chdir(original_cwd)

    def test_load_from_explicit_path(self, tmp_path: Path) -> None:
        """Test loading from explicit config path."""
        config_file = tmp_path / "custom.toml"
        config_file.write_text(
            """
[attack]
depth = 15
"""
        )

        config = ConfigService(config_path=config_file).load()
        assert config.attack.depth == 15

    def test_missing_explicit_path_raises(self, tmp_path: Path) -> None:
        """Test that missing explicit path raises error."""
        with pytest.raises(Exception):
            ConfigService(config_path=tmp_path / "nonexistent.toml").load()


class TestEnvironmentVariables:
    """Tests for environment variable loading."""

    def test_env_overrides_defaults(self) -> None:
        """Test that environment variables override defaults."""
        with mock.patch.dict(os.environ, {"SERIX_DEPTH": "20"}):
            config = ConfigService().load()
            assert config.attack.depth == 20

    def test_env_boolean_parsing(self) -> None:
        """Test that boolean env vars are parsed correctly."""
        with mock.patch.dict(os.environ, {"SERIX_VERBOSE": "true"}):
            config = ConfigService().load()
            assert config.verbose is True

        with mock.patch.dict(os.environ, {"SERIX_VERBOSE": "false"}):
            config = ConfigService().load()
            assert config.verbose is False

    def test_env_model_override(self) -> None:
        """Test overriding model names via env."""
        with mock.patch.dict(os.environ, {"SERIX_JUDGE_MODEL": "gpt-4-turbo"}):
            config = ConfigService().load()
            assert config.models.judge == "gpt-4-turbo"


class TestCliArgs:
    """Tests for CLI argument application."""

    def test_cli_overrides_defaults(self) -> None:
        """Test that CLI args override defaults."""
        config = ConfigService().load(cli_args={"depth": 25})
        assert config.attack.depth == 25

    def test_cli_overrides_file(self, tmp_path: Path) -> None:
        """Test that CLI args override file config."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text(
            """
[attack]
depth = 10
"""
        )

        config = ConfigService(config_path=config_file).load(cli_args={"depth": 30})
        assert config.attack.depth == 30

    def test_cli_skip_regression_inverts(self) -> None:
        """Test that skip_regression inverts to enabled=False."""
        config = ConfigService().load(cli_args={"skip_regression": True})
        assert config.regression.enabled is False

    def test_cli_none_values_ignored(self) -> None:
        """Test that None CLI values don't override defaults."""
        config = ConfigService().load(cli_args={"depth": None})
        assert config.attack.depth == 5  # Default

    def test_cli_verbose(self) -> None:
        """Test verbose flag."""
        config = ConfigService().load(cli_args={"verbose": True})
        assert config.verbose is True


class TestCascadePriority:
    """Tests for cascade priority: CLI > Env > File > Defaults."""

    def test_cascade_cli_wins(self, tmp_path: Path) -> None:
        """Test that CLI has highest priority."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text(
            """
[attack]
depth = 10
"""
        )

        with mock.patch.dict(os.environ, {"SERIX_DEPTH": "15"}):
            config = ConfigService(config_path=config_file).load(cli_args={"depth": 20})
            assert config.attack.depth == 20  # CLI wins

    def test_cascade_env_over_file(self, tmp_path: Path) -> None:
        """Test that env overrides file."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text(
            """
[attack]
depth = 10
"""
        )

        with mock.patch.dict(os.environ, {"SERIX_DEPTH": "15"}):
            config = ConfigService(config_path=config_file).load()
            assert config.attack.depth == 15  # Env wins over file


class TestEnvValueParsing:
    """Tests for environment variable value parsing."""

    def test_parse_integer(self) -> None:
        """Test parsing integer values."""
        with mock.patch.dict(os.environ, {"SERIX_DEPTH": "42"}):
            config = ConfigService().load()
            assert config.attack.depth == 42
            assert isinstance(config.attack.depth, int)

    def test_parse_boolean_variants(self) -> None:
        """Test parsing various boolean representations."""
        for true_val in ["true", "True", "TRUE", "1", "yes", "on"]:
            with mock.patch.dict(os.environ, {"SERIX_VERBOSE": true_val}):
                config = ConfigService().load()
                assert config.verbose is True, f"Failed for {true_val}"

        for false_val in ["false", "False", "FALSE", "0", "no", "off"]:
            with mock.patch.dict(os.environ, {"SERIX_VERBOSE": false_val}):
                config = ConfigService().load()
                assert config.verbose is False, f"Failed for {false_val}"
