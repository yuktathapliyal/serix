"""Core module - client wrapper and data types."""

from serix.core.client import SerixClient
from serix.core.config_loader import SerixFileConfig, find_config_file, load_config
from serix.core.recorder import load_recording, save_recording
from serix.core.types import (
    FuzzConfig,
    RecordedInteraction,
    RecordedRequest,
    RecordedResponse,
    RecordingSession,
    SerixConfig,
    SerixMode,
)

__all__ = [
    # Client
    "SerixClient",
    # Configuration
    "SerixConfig",
    "SerixMode",
    "FuzzConfig",
    "SerixFileConfig",
    "load_config",
    "find_config_file",
    # Recording
    "RecordingSession",
    "RecordedInteraction",
    "RecordedRequest",
    "RecordedResponse",
    "load_recording",
    "save_recording",
]
