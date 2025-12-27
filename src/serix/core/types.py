"""Data models for Serix."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class SerixMode(str, Enum):
    """Operating mode for Serix."""

    PASSTHROUGH = "passthrough"  # Just intercept and log
    RECORD = "record"  # Record interactions to file
    REPLAY = "replay"  # Replay from recorded file
    FUZZ = "fuzz"  # Apply mutations to responses


class RecordedRequest(BaseModel):
    """Captured OpenAI API request."""

    model: str
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    timestamp: datetime = Field(default_factory=datetime.now)
    extra_kwargs: dict[str, Any] = Field(default_factory=dict)


class RecordedResponse(BaseModel):
    """Captured OpenAI API response."""

    id: str
    model: str
    choices: list[dict[str, Any]]
    usage: dict[str, Any] | None = None  # Can contain nested dicts (token details)
    created: int
    object: str = "chat.completion"


class RecordedInteraction(BaseModel):
    """A single request/response pair."""

    request: RecordedRequest
    response: RecordedResponse
    latency_ms: float
    index: int  # Sequential index for replay matching


class RecordingSession(BaseModel):
    """A complete recording session."""

    version: str = "1.0"
    created_at: datetime = Field(default_factory=datetime.now)
    script_path: str | None = None
    interactions: list[RecordedInteraction] = Field(default_factory=list)

    def add_interaction(
        self,
        request: RecordedRequest,
        response: RecordedResponse,
        latency_ms: float,
    ) -> None:
        """Add a new interaction with auto-incrementing index."""
        interaction = RecordedInteraction(
            request=request,
            response=response,
            latency_ms=latency_ms,
            index=len(self.interactions),
        )
        self.interactions.append(interaction)


class FuzzConfig(BaseModel):
    """Configuration for fuzzing mutations."""

    enable_latency: bool = True
    latency_seconds: float = 5.0
    enable_errors: bool = True
    error_codes: list[int] = Field(default_factory=lambda: [500, 503, 429])
    enable_json_corruption: bool = True
    mutation_probability: float = 0.3  # Probability of applying any mutation


class SerixConfig(BaseModel):
    """Global configuration for Serix."""

    mode: SerixMode = SerixMode.PASSTHROUGH
    recording_dir: str = "recordings"
    recording_file: str | None = None  # For replay mode
    fuzz: FuzzConfig = Field(default_factory=FuzzConfig)
    verbose: bool = False


# ============================================================
# v0.3.0 CONFIG TYPES
# ============================================================


class ModelConfig(BaseModel):
    """Model configuration for LLM operations."""

    attacker: str = "gpt-4o-mini"
    judge: str = "gpt-4o"
    critic: str = "gpt-4o-mini"
    patcher: str = "gpt-4o"
    analyzer: str = "gpt-4o-mini"


class TargetConfig(BaseModel):
    """Target configuration."""

    path: str = ""
    name: str = ""
    id: str = ""
    input_field: str = "message"
    output_field: str = "response"
    headers: dict[str, str] = Field(default_factory=dict)
    headers_file: str = ""


class AttackConfig(BaseModel):
    """Attack configuration."""

    goal: str | list[str] = ""
    goals_file: str = ""
    mode: Literal["adaptive", "static"] = "adaptive"
    depth: int = 5
    scenarios: str | list[str] = "all"


class RegressionConfig(BaseModel):
    """Regression check configuration."""

    enabled: bool = True
    skip_mitigated: bool = False


class OutputConfig(BaseModel):
    """Output/report configuration."""

    report: str = "serix-report.html"
    no_report: bool = False
    dry_run: bool = False
    github: bool = False


class FullSerixConfig(BaseModel):
    """Complete configuration (mirrors serix.toml structure)."""

    target: TargetConfig = Field(default_factory=TargetConfig)
    attack: AttackConfig = Field(default_factory=AttackConfig)
    regression: RegressionConfig = Field(default_factory=RegressionConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    models: ModelConfig = Field(default_factory=ModelConfig)
    fuzz: FuzzConfig = Field(default_factory=FuzzConfig)
    live: bool = False
    exhaustive: bool = False
    no_patch: bool = False
    verbose: bool = False
    yes: bool = False


# ============================================================
# STORAGE TYPES
# ============================================================


class TargetMetadata(BaseModel):
    """Metadata stored in .serix/targets/<id>/metadata.json."""

    schema_version: int = 1
    target_id: str
    target_type: str  # "python:function", "python:class", "http"
    locator: str
    name: str | None = None
    created_at: datetime = Field(default_factory=datetime.now)


class StoredAttack(BaseModel):
    """An attack stored in the attack library."""

    id: str
    target_id: str
    goal: str
    strategy_id: str
    payload: str
    status: Literal["exploited", "defended"]
    owasp_code: str | None = None
    confidence: float = 0.0
    created_at: datetime = Field(default_factory=datetime.now)
    last_tested: datetime = Field(default_factory=datetime.now)
    serix_version: str = ""


class AttackLibrary(BaseModel):
    """Attack library for a target."""

    schema_version: int = 1
    target_id: str
    attacks: list[StoredAttack] = Field(default_factory=list)


class IndexFile(BaseModel):
    """Index mapping aliases to target IDs."""

    schema_version: int = 1
    aliases: dict[str, str] = Field(default_factory=dict)


# ============================================================
# RESULT TYPES
# ============================================================


class JudgeResult(BaseModel):
    """Result from judge evaluation."""

    success: bool
    confidence: float
    reasoning: str
    owasp_code: str | None = None


class AttackResult(BaseModel):
    """Result from a single attack attempt."""

    success: bool
    persona: str
    goal: str
    turns_taken: int
    confidence: float
    winning_payload: str | None = None
    owasp_code: str | None = None
    conversation: list[dict[str, Any]] = Field(default_factory=list)
    judge_reasoning: str = ""


class WorkflowResult(BaseModel):
    """Result from a complete workflow run."""

    passed: bool
    total_attacks: int
    exploited: int
    defended: int
    duration_seconds: float
    exit_code: int
    attacks: list[AttackResult] = Field(default_factory=list)
