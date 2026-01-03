"""
Serix v2 Config - Resolution Logic

Merges CLI flags, environment variables, TOML config, and defaults
into a single SerixSessionConfig.

Priority: CLI > Environment Variables > TOML Config > Defaults
"""

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from serix_v2.core import constants
from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import AttackMode
from serix_v2.core.errors import ConfigValidationError

from .models import TomlConfig
from .utils import parse_env_value, read_goals_file, read_headers_file, resolve_path


class CLIOverrides(BaseModel):
    """
    CLI-provided values that override config file settings.
    All fields are Optional - only set values override.
    """

    # Target
    target_path: str | None = None
    target_name: str | None = None
    target_id: str | None = None
    input_field: str | None = None
    output_field: str | None = None
    headers: dict[str, str] | None = None
    headers_file: str | None = None

    # Attack
    goals: list[str] | None = None
    goals_file: str | None = None
    mode: str | None = None
    scenarios: list[str] | None = None
    depth: int | None = None
    exhaustive: bool | None = None

    # Models
    attacker_model: str | None = None
    judge_model: str | None = None
    critic_model: str | None = None
    patcher_model: str | None = None
    analyzer_model: str | None = None

    # Fuzz
    fuzz: bool | None = None
    fuzz_only: bool | None = None
    fuzz_latency: float | None = None
    fuzz_errors: bool | None = None
    fuzz_json: bool | None = None
    fuzz_probability: float | None = None

    # Regression
    skip_regression: bool | None = None
    skip_mitigated: bool | None = None

    # Output
    report_path: str | None = None
    no_report: bool | None = None
    dry_run: bool | None = None
    github: bool | None = None

    # Behavior
    no_patch: bool | None = None
    system_prompt: str | None = None
    live: bool | None = None
    verbose: bool | None = None
    yes: bool | None = None


# Environment variable mapping: ENV_NAME -> (field_name, type)
ENV_VAR_MAP: dict[str, tuple[str, type]] = {
    "SERIX_TARGET_PATH": ("target_path", str),
    "SERIX_DEPTH": ("depth", int),
    "SERIX_MODE": ("mode", str),
    "SERIX_ATTACKER_MODEL": ("attacker_model", str),
    "SERIX_JUDGE_MODEL": ("judge_model", str),
    "SERIX_CRITIC_MODEL": ("critic_model", str),
    "SERIX_PATCHER_MODEL": ("patcher_model", str),
    "SERIX_ANALYZER_MODEL": ("analyzer_model", str),
    "SERIX_VERBOSE": ("verbose", bool),
    "SERIX_DRY_RUN": ("dry_run", bool),
    "SERIX_GITHUB": ("github", bool),
    "SERIX_EXHAUSTIVE": ("exhaustive", bool),
    "SERIX_FUZZ_PROBABILITY": ("fuzz_probability", float),
}


def load_env_overrides() -> dict[str, Any]:
    """
    Load configuration overrides from environment variables.

    Scans os.environ for keys starting with SERIX_ and maps them
    to SerixSessionConfig field names.

    Returns:
        Dict of field_name -> value for non-None env overrides.
    """
    result: dict[str, Any] = {}

    for env_name, (field_name, field_type) in ENV_VAR_MAP.items():
        value = os.environ.get(env_name)
        if value is not None:
            try:
                result[field_name] = parse_env_value(value, field_type)
            except ValueError:
                # Invalid value - skip silently or log warning
                pass

    return result


def resolve_goals(
    cli_goals: list[str] | None,
    cli_goals_file: str | None,
    toml_goals_file: str | None,
    toml_goals: list[str] | None,
    toml_goal: str | list[str] | None,
    config_dir: Path | None,
) -> list[str]:
    """
    Resolve goals with correct priority (first non-empty wins, NO merging).

    Priority:
        1. CLI --goals-file       → Read from file
        2. CLI --goal (repeated)  → From command line
        3. Config goals_file      → Read from file
        4. Config goals (array)   → Use array
        5. Config goal (str|list) → Convert to list
        6. Default goal           → From constants.py

    Args:
        cli_goals: Goals from CLI --goal flags.
        cli_goals_file: Path from CLI --goals-file flag.
        toml_goals_file: Path from config [attack].goals_file.
        toml_goals: List from config [attack].goals.
        toml_goal: String or list from config [attack].goal.
        config_dir: Directory containing config file (for relative path resolution).

    Returns:
        List of goal strings.
    """
    # 1. CLI --goals-file wins first
    if cli_goals_file:
        # CLI paths resolve against CWD
        return read_goals_file(Path(cli_goals_file))

    # 2. CLI --goal flags
    if cli_goals:
        return cli_goals

    # 3. Config goals_file
    if toml_goals_file and config_dir:
        resolved = resolve_path(toml_goals_file, config_dir)
        return read_goals_file(resolved)

    # 4. Config goals array
    if toml_goals:
        return toml_goals

    # 5. Config goal (string or list)
    if toml_goal:
        if isinstance(toml_goal, list):
            return toml_goal
        return [toml_goal]

    # 6. Default goal
    return [constants.DEFAULT_GOAL]


def resolve_scenarios(
    cli_scenarios: list[str] | None,
    toml_scenarios: str | list[str] | None,
) -> list[str]:
    """
    Resolve scenarios with type normalization.

    Args:
        cli_scenarios: Scenarios from CLI (already a list).
        toml_scenarios: Scenarios from config (string or list).

    Returns:
        List of scenario strings.
    """
    if cli_scenarios:
        return cli_scenarios

    if toml_scenarios:
        if isinstance(toml_scenarios, list):
            return toml_scenarios
        return [toml_scenarios]

    return constants.DEFAULT_SCENARIOS.copy()


def resolve_fuzz_latency(
    cli_fuzz_latency: float | None,
    toml_latency: bool | float | None,
    toml_latency_seconds: float | None,
) -> float | None:
    """
    Resolve fuzz latency with type coercion.

    Args:
        cli_fuzz_latency: Latency from CLI --fuzz-latency.
        toml_latency: Latency from config [fuzz].latency (bool or float).
        toml_latency_seconds: Latency from config [fuzz].latency_seconds (backward compat).

    Returns:
        Latency in seconds, or None if disabled.
    """
    # CLI wins
    if cli_fuzz_latency is not None:
        return cli_fuzz_latency

    # TOML latency field
    if toml_latency is not None:
        if isinstance(toml_latency, bool):
            if toml_latency:
                # latency = true → use default or latency_seconds
                return toml_latency_seconds or constants.DEFAULT_FUZZ_LATENCY
            else:
                # latency = false → disabled
                return None
        else:
            # latency = 5.0 → use directly
            return toml_latency

    return None


def resolve_skip_regression(
    cli_skip_regression: bool | None,
    toml_enabled: bool | None,
) -> bool:
    """
    Resolve skip_regression with inversion from [regression].enabled.

    Args:
        cli_skip_regression: From CLI --skip-regression.
        toml_enabled: From config [regression].enabled.

    Returns:
        True if regression should be skipped.
    """
    # CLI wins
    if cli_skip_regression is not None:
        return cli_skip_regression

    # Invert: enabled=true → skip=False, enabled=false → skip=True
    if toml_enabled is not None:
        return not toml_enabled

    return False  # Default: don't skip


def resolve_exhaustive(
    cli_exhaustive: bool | None,
    toml_exhaustive: bool | None,
    toml_stop_on_first: bool | None,
) -> bool:
    """
    Resolve exhaustive with backward compat for stop_on_first.

    Args:
        cli_exhaustive: From CLI --exhaustive.
        toml_exhaustive: From config root-level exhaustive.
        toml_stop_on_first: From config [attack].stop_on_first (backward compat).

    Returns:
        True if exhaustive mode is enabled.
    """
    # CLI wins
    if cli_exhaustive is not None:
        return cli_exhaustive

    # Root-level exhaustive
    if toml_exhaustive is not None:
        return toml_exhaustive

    # Backward compat: stop_on_first is inverted
    if toml_stop_on_first is not None:
        return not toml_stop_on_first

    return False  # Default


def _first_non_none(*values: Any) -> Any:
    """Return first non-None value, or None if all are None."""
    for v in values:
        if v is not None:
            return v
    return None


def resolve_config(
    cli: CLIOverrides,
    toml: TomlConfig | None = None,
    config_dir: Path | None = None,
) -> SerixSessionConfig:
    """
    Merge CLI overrides, env vars, TOML config, and defaults into SerixSessionConfig.

    Priority: CLI > Environment Variables > TOML > defaults (from constants.py)

    Args:
        cli: CLI-provided overrides (from Typer command).
        toml: Pre-loaded TOML config. If None, uses empty TomlConfig.
        config_dir: Directory containing config file (for resolving relative paths).
                    If None, relative paths in config are resolved against CWD.

    Returns:
        Fully resolved SerixSessionConfig.

    Raises:
        ConfigValidationError: If required fields missing (e.g., target_path).

    Note:
        - CLI paths are resolved against CWD (user's working directory)
        - Config file paths are resolved against config_dir (where serix.toml lives)
    """
    if toml is None:
        toml = TomlConfig()

    # Use CWD as fallback for config_dir
    if config_dir is None:
        config_dir = Path.cwd()

    # Load environment variable overrides
    env_overrides = load_env_overrides()

    # ========================================================================
    # TARGET
    # ========================================================================
    # Priority: CLI > Env > TOML path > TOML script (backward compat)
    target_path = _first_non_none(
        cli.target_path,
        env_overrides.get("target_path"),
        toml.target.path,
        toml.target.script,  # Backward compat
    )

    if target_path is None:
        raise ConfigValidationError(
            field="target_path",
            message="target_path is required. Provide via CLI argument, config file, or SERIX_TARGET_PATH env var.",
        )

    target_name = _first_non_none(cli.target_name, toml.target.name)
    target_id = _first_non_none(cli.target_id, toml.target.id)

    input_field = _first_non_none(
        cli.input_field,
        toml.target.input_field,
        constants.DEFAULT_INPUT_FIELD,
    )

    output_field = _first_non_none(
        cli.output_field,
        toml.target.output_field,
        constants.DEFAULT_OUTPUT_FIELD,
    )

    # Headers: CLI > headers_file > TOML headers
    headers: dict[str, str] = {}
    if cli.headers:
        headers = cli.headers
    elif cli.headers_file:
        # CLI path resolves against CWD
        headers = read_headers_file(Path(cli.headers_file))
    elif toml.target.headers_file:
        # Config path resolves against config_dir
        resolved = resolve_path(toml.target.headers_file, config_dir)
        headers = read_headers_file(resolved)
    elif toml.target.headers:
        headers = toml.target.headers

    # ========================================================================
    # ATTACK
    # ========================================================================
    goals = resolve_goals(
        cli_goals=cli.goals,
        cli_goals_file=cli.goals_file,
        toml_goals_file=toml.attack.goals_file,
        toml_goals=toml.attack.goals,
        toml_goal=toml.attack.goal,
        config_dir=config_dir,
    )

    mode_str = _first_non_none(
        cli.mode,
        env_overrides.get("mode"),
        toml.attack.mode,
        constants.DEFAULT_MODE,
    )
    mode = AttackMode(mode_str)

    scenarios = resolve_scenarios(cli.scenarios, toml.attack.scenarios)

    depth = _first_non_none(
        cli.depth,
        env_overrides.get("depth"),
        toml.attack.depth,
        toml.attack.max_attempts,  # Backward compat
        constants.DEFAULT_DEPTH,
    )

    exhaustive = resolve_exhaustive(
        cli.exhaustive,
        env_overrides.get("exhaustive"),
        toml.attack.stop_on_first,
    )

    # ========================================================================
    # MODELS
    # ========================================================================
    attacker_model = _first_non_none(
        cli.attacker_model,
        env_overrides.get("attacker_model"),
        toml.models.attacker,
        constants.DEFAULT_ATTACKER_MODEL,
    )

    judge_model = _first_non_none(
        cli.judge_model,
        env_overrides.get("judge_model"),
        toml.models.judge,
        constants.DEFAULT_JUDGE_MODEL,
    )

    critic_model = _first_non_none(
        cli.critic_model,
        env_overrides.get("critic_model"),
        toml.models.critic,
        constants.DEFAULT_CRITIC_MODEL,
    )

    patcher_model = _first_non_none(
        cli.patcher_model,
        env_overrides.get("patcher_model"),
        toml.models.patcher,
        constants.DEFAULT_PATCHER_MODEL,
    )

    analyzer_model = _first_non_none(
        cli.analyzer_model,
        env_overrides.get("analyzer_model"),
        toml.models.analyzer,
        constants.DEFAULT_ANALYZER_MODEL,
    )

    # ========================================================================
    # FUZZ
    # ========================================================================
    fuzz = _first_non_none(cli.fuzz, toml.fuzz.enabled, False)
    fuzz_only = _first_non_none(cli.fuzz_only, toml.fuzz.only, False)

    fuzz_latency = resolve_fuzz_latency(
        cli.fuzz_latency,
        toml.fuzz.latency,
        toml.fuzz.latency_seconds,
    )

    fuzz_errors = _first_non_none(cli.fuzz_errors, toml.fuzz.errors, False)

    # json_enabled uses alias "json" from TOML
    fuzz_json = _first_non_none(
        cli.fuzz_json,
        toml.fuzz.json_enabled,
        toml.fuzz.json_corruption,  # Backward compat
        False,
    )

    fuzz_probability = _first_non_none(
        cli.fuzz_probability,
        env_overrides.get("fuzz_probability"),
        toml.fuzz.probability,
        toml.fuzz.mutation_probability,  # Backward compat
        constants.DEFAULT_FUZZ_PROBABILITY,
    )

    # ========================================================================
    # REGRESSION
    # ========================================================================
    skip_regression = resolve_skip_regression(
        cli.skip_regression, toml.regression.enabled
    )
    skip_mitigated = _first_non_none(
        cli.skip_mitigated, toml.regression.skip_mitigated, False
    )

    # ========================================================================
    # OUTPUT
    # ========================================================================
    report_path = _first_non_none(
        cli.report_path,
        toml.output.report,
        toml.attack.report,  # Backward compat
        constants.DEFAULT_REPORT_PATH,
    )

    no_report = _first_non_none(cli.no_report, toml.output.no_report, False)
    dry_run = _first_non_none(
        cli.dry_run, env_overrides.get("dry_run"), toml.output.dry_run, False
    )
    github = _first_non_none(
        cli.github, env_overrides.get("github"), toml.output.github, False
    )

    # ========================================================================
    # BEHAVIOR
    # ========================================================================
    no_patch = _first_non_none(cli.no_patch, toml.no_patch, False)
    system_prompt = cli.system_prompt  # CLI only, no config fallback
    live = _first_non_none(cli.live, toml.live, False)
    verbose = _first_non_none(
        cli.verbose, env_overrides.get("verbose"), toml.verbose, False
    )
    yes = _first_non_none(cli.yes, toml.yes, False)

    return SerixSessionConfig(
        # Target
        target_path=target_path,
        target_name=target_name,
        target_id=target_id,
        input_field=input_field,
        output_field=output_field,
        headers=headers,
        headers_file=cli.headers_file or toml.target.headers_file,
        # Attack
        goals=goals,
        goals_file=cli.goals_file or toml.attack.goals_file,
        mode=mode,
        scenarios=scenarios,
        depth=depth,
        exhaustive=exhaustive,
        # Models
        attacker_model=attacker_model,
        judge_model=judge_model,
        critic_model=critic_model,
        patcher_model=patcher_model,
        analyzer_model=analyzer_model,
        # Fuzz
        fuzz=fuzz,
        fuzz_only=fuzz_only,
        fuzz_latency=fuzz_latency,
        fuzz_errors=fuzz_errors,
        fuzz_json=fuzz_json,
        fuzz_probability=fuzz_probability,
        # Regression
        skip_regression=skip_regression,
        skip_mitigated=skip_mitigated,
        # Output
        report_path=report_path,
        no_report=no_report,
        dry_run=dry_run,
        github=github,
        # Behavior
        no_patch=no_patch,
        system_prompt=system_prompt,
        live=live,
        verbose=verbose,
        yes=yes,
    )
