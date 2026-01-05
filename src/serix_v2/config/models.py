"""
Serix v2 Config - TOML Pydantic Models

These models represent the structure of serix.toml and pyproject.toml [tool.serix].
All fields are Optional since config files may be partial.

Law 1 Compliant: No raw dicts between modules - all TOML sections are Pydantic models.
"""

from pydantic import BaseModel, Field


class TomlTargetConfig(BaseModel):
    """[target] section of serix.toml."""

    path: str | None = None
    script: str | None = None  # Backward compat (deprecated, use 'path')
    name: str | None = None
    id: str | None = None
    input_field: str | None = None
    output_field: str | None = None
    headers: dict[str, str] | None = None
    headers_file: str | None = None


class TomlAttackConfig(BaseModel):
    """[attack] section of serix.toml."""

    goal: str | list[str] | None = None  # Can be string OR array in TOML
    goals: list[str] | None = None  # Explicit array form
    goals_file: str | None = None
    mode: str | None = None
    depth: int | None = None
    max_attempts: int | None = None  # Backward compat (deprecated, use 'depth')
    scenarios: str | list[str] | None = None  # Can be string OR array
    report: str | None = None  # Backward compat (moved to [output].report)
    stop_on_first: bool | None = None  # Backward compat (inverted to exhaustive)


class TomlRegressionConfig(BaseModel):
    """[regression] section of serix.toml."""

    enabled: bool | None = None  # INVERTED to skip_regression in SerixSessionConfig
    skip_regression: bool | None = None  # Direct field (takes precedence over enabled)
    skip_mitigated: bool | None = None


class TomlOutputConfig(BaseModel):
    """[output] section of serix.toml."""

    report: str | None = None
    no_report: bool | None = None
    dry_run: bool | None = None
    github: bool | None = None


class TomlModelsConfig(BaseModel):
    """[models] section of serix.toml."""

    attacker: str | None = None
    judge: str | None = None
    critic: str | None = None
    patcher: str | None = None
    analyzer: str | None = None


class TomlFuzzConfig(BaseModel):
    """[fuzz] section of serix.toml."""

    model_config = {"populate_by_name": True}  # Allow both alias and field name

    enabled: bool | None = None
    only: bool | None = None
    latency: bool | float | None = None  # Can be bool OR float seconds
    errors: bool | None = None
    json_enabled: bool | None = Field(default=None, alias="json")  # Short name
    json_corruption: bool | None = None  # Backward compat
    probability: float | None = None
    mutation_probability: float | None = None  # Backward compat (deprecated)
    latency_seconds: float | None = None  # Backward compat (used when latency=true)


class TomlConfig(BaseModel):
    """
    Root configuration from serix.toml or pyproject.toml [tool.serix].

    All sections are optional and default to empty sub-models.
    Missing sections produce default values, not errors.
    """

    # Sections
    target: TomlTargetConfig = Field(default_factory=TomlTargetConfig)
    attack: TomlAttackConfig = Field(default_factory=TomlAttackConfig)
    regression: TomlRegressionConfig = Field(default_factory=TomlRegressionConfig)
    output: TomlOutputConfig = Field(default_factory=TomlOutputConfig)
    models: TomlModelsConfig = Field(default_factory=TomlModelsConfig)
    fuzz: TomlFuzzConfig = Field(default_factory=TomlFuzzConfig)

    # Root-level fields (not in a section)
    verbose: bool | None = None
    yes: bool | None = None
    exhaustive: bool | None = None
    live: bool | None = None
    no_patch: bool | None = None
