"""Configuration file loader for Serix."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from rich.console import Console

console = Console()

# Config file names to search for (in order of priority)
CONFIG_FILES = ["serix.toml", ".serix.toml", "pyproject.toml"]


class ModelConfig(BaseModel):
    """Model configuration for all Serix components."""

    attacker: str = "gpt-4o-mini"  # Generates attacks (cost-effective, runs many times)
    judge: str = "gpt-4o"  # Impartial evaluator (accuracy matters, runs once)
    critic: str = "gpt-4o-mini"  # Per-turn analysis in adversary loop
    patcher: str = "gpt-4o"  # Self-healing prompt generation
    analyzer: str = "gpt-4o-mini"  # Vulnerability classification


class AttackConfig(BaseModel):
    """Configuration for red team attacks."""

    goal: str | None = None
    max_attempts: int = 10
    judge_model: str | None = None  # Deprecated: use [models].judge instead
    model: str | None = None  # Deprecated: use [models].attacker instead
    report: str | None = None
    stop_on_first: bool = True


class FuzzConfig(BaseModel):
    """Configuration for fuzzing."""

    enabled: bool = False
    latency: bool = True
    errors: bool = True
    json_corruption: bool = True
    mutation_probability: float = 0.3
    latency_seconds: float = 5.0


class TargetConfig(BaseModel):
    """Configuration for target scripts."""

    target: str | None = None  # Full target: file.py:function or http://url
    script: str | None = None  # Legacy: just the script file (for attack command)
    working_dir: str | None = None


class SerixFileConfig(BaseModel):
    """Complete Serix configuration from file."""

    target: TargetConfig = Field(default_factory=TargetConfig)
    attack: AttackConfig = Field(default_factory=AttackConfig)
    fuzz: FuzzConfig = Field(default_factory=FuzzConfig)
    models: ModelConfig = Field(default_factory=ModelConfig)
    verbose: bool = False


def find_config_file(start_dir: Path | None = None) -> Path | None:
    """
    Find a Serix config file by walking up the directory tree.

    Args:
        start_dir: Directory to start searching from (default: cwd)

    Returns:
        Path to config file if found, None otherwise
    """
    if start_dir is None:
        start_dir = Path.cwd()

    current = start_dir.resolve()

    # Walk up the directory tree
    while current != current.parent:
        for config_name in CONFIG_FILES:
            config_path = current / config_name
            if config_path.exists():
                # For pyproject.toml, check if it has a [tool.serix] section
                if config_name == "pyproject.toml":
                    try:
                        with open(config_path, "rb") as f:
                            data = tomllib.load(f)
                        if "tool" in data and "serix" in data["tool"]:
                            return config_path
                    except Exception:
                        continue
                else:
                    return config_path
        current = current.parent

    return None


def load_config(config_path: Path | None = None) -> SerixFileConfig:
    """
    Load Serix configuration from a TOML file.

    Args:
        config_path: Path to config file. If None, searches for one.

    Returns:
        SerixFileConfig with loaded values (or defaults if no file found)
    """
    if config_path is None:
        config_path = find_config_file()

    if config_path is None:
        return SerixFileConfig()

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)

        # Handle pyproject.toml vs serix.toml
        if config_path.name == "pyproject.toml":
            config_data = data.get("tool", {}).get("serix", {})
        else:
            config_data = data

        return SerixFileConfig.model_validate(config_data)

    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Failed to load config: {e}")
        return SerixFileConfig()


def merge_config_with_cli(
    file_config: SerixFileConfig,
    cli_args: dict[str, Any],
) -> dict[str, Any]:
    """
    Merge file config with CLI arguments. CLI args take precedence.

    Args:
        file_config: Configuration loaded from file
        cli_args: Arguments passed via CLI

    Returns:
        Merged configuration dictionary
    """
    # Start with file config values
    merged = {
        "script": file_config.target.script,
        "goal": file_config.attack.goal,
        "max_attempts": file_config.attack.max_attempts,
        "judge_model": file_config.attack.judge_model,
        "report": file_config.attack.report,
        "verbose": file_config.verbose,
        "fuzz": file_config.fuzz.enabled,
        "fuzz_latency": file_config.fuzz.latency,
        "fuzz_errors": file_config.fuzz.errors,
        "fuzz_json": file_config.fuzz.json_corruption,
    }

    # Override with CLI args (if provided and not None/default)
    for key, value in cli_args.items():
        if value is not None:
            # Special handling for boolean flags that default to False
            if key in ("verbose", "fuzz", "fuzz_latency", "fuzz_errors", "fuzz_json"):
                if value:  # Only override if explicitly set to True
                    merged[key] = value
            else:
                merged[key] = value

    return merged


# Cached config for get_models() singleton
_cached_config: SerixFileConfig | None = None


def get_models() -> ModelConfig:
    """Get model configuration from serix.toml (cached singleton).

    Loads config once and caches it. Falls back to defaults if no config file.
    Also respects legacy [attack].model and [attack].judge_model if set.
    """
    global _cached_config

    if _cached_config is None:
        _cached_config = load_config()

        # Backward compat: if legacy attack.model/judge_model are set, use them
        if _cached_config.attack.model:
            _cached_config.models.attacker = _cached_config.attack.model
        if _cached_config.attack.judge_model:
            _cached_config.models.judge = _cached_config.attack.judge_model

    return _cached_config.models


def reset_model_cache() -> None:
    """Reset the cached config. Useful for testing."""
    global _cached_config
    _cached_config = None
