"""Serix - AI agent testing framework."""

from serix.core.client import SerixClient
from serix.core.config_loader import SerixFileConfig, load_config
from serix.core.types import (
    FuzzConfig,
    RecordedInteraction,
    RecordingSession,
    SerixConfig,
    SerixMode,
)
from serix.fuzz.redteam import Attack, AttackResults, RedTeamEngine

__version__ = "0.1.0"
__all__ = [
    # Core
    "SerixClient",
    "SerixConfig",
    "SerixMode",
    "FuzzConfig",
    # Config
    "SerixFileConfig",
    "load_config",
    # Recording
    "RecordingSession",
    "RecordedInteraction",
    # Red Team
    "RedTeamEngine",
    "Attack",
    "AttackResults",
]
