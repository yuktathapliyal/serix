"""Data models for Serix."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

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
