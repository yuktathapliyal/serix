"""
Serix v2 Core - The DNA

This package has ZERO imports from other serix_v2 packages.
All other packages depend on core, never the reverse.
"""

from .config import SerixSessionConfig
from .constants import APP_DIR, APP_NAME, CONFIG_FILENAME
from .contracts import (  # Enums; Model outputs; Scoring; Execution units; Storage models
    AttackLibrary,
    AttackMode,
    AttackResult,
    AttackStatus,
    AttackTurn,
    CampaignResult,
    CriticFeedback,
    Grade,
    HealingPatch,
    HealingResult,
    JudgeVerdict,
    Persona,
    ResilienceResult,
    ScoreAxis,
    SecurityScore,
    Severity,
    StoredAttack,
    TargetIndex,
    TargetMetadata,
    TargetType,
    ToolRecommendation,
    VulnerabilityAnalysis,
)
from .id_gen import generate_attack_id, generate_run_id, generate_target_id

__all__ = [
    # Constants
    "APP_NAME",
    "APP_DIR",
    "CONFIG_FILENAME",
    # Enums
    "AttackStatus",
    "AttackMode",
    "Persona",
    "TargetType",
    "Severity",
    "Grade",
    # Model outputs
    "CriticFeedback",
    "JudgeVerdict",
    "VulnerabilityAnalysis",
    "HealingPatch",
    "ToolRecommendation",
    "HealingResult",
    # Scoring
    "ScoreAxis",
    "SecurityScore",
    # Execution units
    "AttackTurn",
    "AttackResult",
    "ResilienceResult",
    "CampaignResult",
    # Storage models
    "StoredAttack",
    "AttackLibrary",
    "TargetMetadata",
    "TargetIndex",
    # Config
    "SerixSessionConfig",
    # ID Generation
    "generate_target_id",
    "generate_run_id",
    "generate_attack_id",
]
