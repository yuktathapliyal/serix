"""
Serix v2 Config - TOML Configuration Loading and Resolution

This module provides the config loading infrastructure:
- TomlConfig: Pydantic model for serix.toml / pyproject.toml [tool.serix]
- CLIOverrides: Pydantic model for CLI-provided values
- find_config_file(): Walk up directory tree to find config file
- load_toml_config(): Parse TOML file into TomlConfig
- resolve_config(): Merge CLI + env + TOML + defaults → SerixSessionConfig

Usage:
    from serix_v2.config import find_config_file, load_toml_config, resolve_config, CLIOverrides

    # Load config file
    toml_config, config_dir = load_toml_config()

    # Create CLI overrides from Typer command
    cli = CLIOverrides(target_path="agent.py:fn", depth=10)

    # Resolve to final config
    session_config = resolve_config(cli, toml_config, config_dir)
"""

from .loader import find_config_file, load_toml_config
from .models import (
    TomlAttackConfig,
    TomlConfig,
    TomlFuzzConfig,
    TomlModelsConfig,
    TomlOutputConfig,
    TomlRegressionConfig,
    TomlTargetConfig,
)
from .resolver import CLIOverrides, resolve_config
from .utils import read_goals_file, read_headers_file, resolve_path

__all__ = [
    # Main functions
    "find_config_file",
    "load_toml_config",
    "resolve_config",
    # Models
    "CLIOverrides",
    "TomlConfig",
    "TomlTargetConfig",
    "TomlAttackConfig",
    "TomlRegressionConfig",
    "TomlOutputConfig",
    "TomlModelsConfig",
    "TomlFuzzConfig",
    # Utilities
    "resolve_path",
    "read_goals_file",
    "read_headers_file",
]
