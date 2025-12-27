"""Configuration service with cascade loading.

Loads configuration with priority: CLI > Environment > File > Defaults.

Supports loading from:
- serix.toml (project config)
- pyproject.toml [tool.serix] section
- Environment variables (SERIX_* prefix)
- CLI arguments (highest priority)
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from ..core.constants import (
    CONFIG_FILENAME,
    CONFIG_FILENAME_HIDDEN,
    ENV_PREFIX,
    PYPROJECT_FILENAME,
    PYPROJECT_SECTION,
)
from ..core.errors import ConfigError
from ..core.types import FullSerixConfig


class ConfigService:
    """Service for loading configuration with cascade priority.

    Priority (highest to lowest):
    1. CLI arguments
    2. Environment variables (SERIX_*)
    3. Config file (serix.toml or pyproject.toml)
    4. Defaults (from FullSerixConfig)

    Example:
        config_service = ConfigService()
        config = config_service.load(cli_args={"depth": 10, "verbose": True})
    """

    def __init__(self, config_path: Path | None = None) -> None:
        """Initialize config service.

        Args:
            config_path: Explicit path to config file (optional)
        """
        self._config_path = config_path

    def load(
        self,
        cli_args: dict[str, Any] | None = None,
    ) -> FullSerixConfig:
        """Load configuration with cascade priority.

        Args:
            cli_args: Command-line arguments (highest priority)

        Returns:
            Merged configuration with all sources applied
        """
        # 1. Start with defaults
        config = FullSerixConfig()

        # 2. Load from file (if exists)
        file_config = self._load_from_file()
        if file_config:
            config = self._merge_configs(config, file_config)

        # 3. Apply environment variables
        env_config = self._load_from_env()
        if env_config:
            config = self._merge_configs(config, env_config)

        # 4. Apply CLI args (highest priority)
        if cli_args:
            config = self._apply_cli_args(config, cli_args)

        return config

    def _load_from_file(self) -> dict[str, Any] | None:
        """Load config from serix.toml or pyproject.toml.

        Search order:
        1. Explicit path (if provided)
        2. serix.toml in current directory
        3. .serix.toml in current directory
        4. pyproject.toml [tool.serix] in current directory

        Returns:
            Config dict if found, None otherwise
        """
        # Try explicit path first
        if self._config_path:
            if self._config_path.exists():
                return self._parse_toml(self._config_path)
            raise ConfigError(f"Config file not found: {self._config_path}")

        # Try serix.toml
        serix_toml = Path.cwd() / CONFIG_FILENAME
        if serix_toml.exists():
            return self._parse_toml(serix_toml)

        # Try .serix.toml (hidden)
        hidden_toml = Path.cwd() / CONFIG_FILENAME_HIDDEN
        if hidden_toml.exists():
            return self._parse_toml(hidden_toml)

        # Try pyproject.toml [tool.serix]
        pyproject = Path.cwd() / PYPROJECT_FILENAME
        if pyproject.exists():
            data = self._parse_toml(pyproject)
            if data:
                # Navigate to tool.serix section
                parts = PYPROJECT_SECTION.split(".")
                for part in parts:
                    if isinstance(data, dict):
                        data = data.get(part)
                    else:
                        return None
                return data if isinstance(data, dict) else None

        return None

    def _parse_toml(self, path: Path) -> dict[str, Any] | None:
        """Parse a TOML file.

        Args:
            path: Path to TOML file

        Returns:
            Parsed dict or None on error

        Raises:
            ConfigError: If file exists but can't be parsed
        """
        try:
            with open(path, "rb") as f:
                return tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"Invalid TOML in {path}: {e}")
        except OSError as e:
            raise ConfigError(f"Cannot read {path}: {e}")

    def _load_from_env(self) -> dict[str, Any]:
        """Load config from environment variables.

        Looks for SERIX_* environment variables and maps them
        to config paths. Values are parsed to appropriate types.

        Examples:
            SERIX_DEPTH=10 -> {"attack": {"depth": 10}}
            SERIX_VERBOSE=true -> {"verbose": True}
            SERIX_JUDGE_MODEL=gpt-4 -> {"models": {"judge": "gpt-4"}}

        Returns:
            Config dict from environment variables
        """
        config: dict[str, Any] = {}

        # Map env vars to config paths
        env_mapping: dict[str, tuple[str, ...]] = {
            "DEPTH": ("attack", "depth"),
            "GOAL": ("attack", "goal"),
            "MODE": ("attack", "mode"),
            "SCENARIOS": ("attack", "scenarios"),
            "JUDGE_MODEL": ("models", "judge"),
            "ATTACKER_MODEL": ("models", "attacker"),
            "CRITIC_MODEL": ("models", "critic"),
            "PATCHER_MODEL": ("models", "patcher"),
            "ANALYZER_MODEL": ("models", "analyzer"),
            "VERBOSE": ("verbose",),
            "LIVE": ("live",),
            "EXHAUSTIVE": ("exhaustive",),
        }

        for env_suffix, config_path in env_mapping.items():
            env_key = f"{ENV_PREFIX}{env_suffix}"
            value = os.environ.get(env_key)
            if value is not None:
                parsed_value = self._parse_env_value(value)
                # Set nested value
                current = config
                for key in config_path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                current[config_path[-1]] = parsed_value

        return config

    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable value to appropriate type.

        Pydantic expects typed values, so we convert strings to:
        - bool: "true", "1", "yes" -> True; "false", "0", "no" -> False
        - int: numeric strings
        - float: decimal strings
        - str: everything else

        Args:
            value: String value from environment

        Returns:
            Parsed value with appropriate type
        """
        # Boolean
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        if value.lower() in ("false", "0", "no", "off"):
            return False

        # Integer
        try:
            return int(value)
        except ValueError:
            pass

        # Float
        try:
            return float(value)
        except ValueError:
            pass

        # String (default)
        return value

    def _merge_configs(
        self,
        base: FullSerixConfig,
        override: dict[str, Any],
    ) -> FullSerixConfig:
        """Merge override dict into base config.

        Args:
            base: Base configuration
            override: Dict to merge on top

        Returns:
            New config with merged values
        """
        base_dict = base.model_dump()
        self._deep_merge(base_dict, override)
        return FullSerixConfig.model_validate(base_dict)

    def _deep_merge(
        self,
        base: dict[str, Any],
        override: dict[str, Any],
    ) -> None:
        """Deep merge override into base (mutates base).

        Recursively merges nested dicts. Non-dict values are replaced.

        Args:
            base: Base dict to merge into (mutated)
            override: Dict with values to override
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _apply_cli_args(
        self,
        config: FullSerixConfig,
        cli_args: dict[str, Any],
    ) -> FullSerixConfig:
        """Apply CLI arguments to config.

        Only applies non-None values. Handles special cases like
        skip_regression (inverted to regression.enabled).

        Args:
            config: Base configuration
            cli_args: CLI arguments dict

        Returns:
            Config with CLI args applied
        """
        config_dict = config.model_dump()

        # Map CLI args to config paths
        cli_mapping: dict[str, tuple[str, ...]] = {
            "goal": ("attack", "goal"),
            "goals": ("attack", "goal"),
            "depth": ("attack", "depth"),
            "scenarios": ("attack", "scenarios"),
            "mode": ("attack", "mode"),
            "name": ("target", "name"),
            "target_id": ("target", "id"),
            "skip_regression": ("regression", "enabled"),  # Inverted
            "skip_mitigated": ("regression", "skip_mitigated"),
            "report": ("output", "report"),
            "no_report": ("output", "no_report"),
            "dry_run": ("output", "dry_run"),
            "github": ("output", "github"),
            "verbose": ("verbose",),
            "live": ("live",),
            "exhaustive": ("exhaustive",),
            "no_patch": ("no_patch",),
            "yes": ("yes",),
        }

        for cli_key, config_path in cli_mapping.items():
            value = cli_args.get(cli_key)
            if value is None:
                continue

            # Handle inversions
            if cli_key == "skip_regression":
                value = not value  # skip_regression=True -> enabled=False

            # Handle list/string conversions for scenarios
            if cli_key == "scenarios" and isinstance(value, str):
                value = [value]

            # Set nested value
            current = config_dict
            for key in config_path[:-1]:
                current = current[key]
            current[config_path[-1]] = value

        return FullSerixConfig.model_validate(config_dict)
