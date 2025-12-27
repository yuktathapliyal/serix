"""Serix - AI agent testing framework."""

from importlib.metadata import version as _get_version

from serix.core.client import SerixClient
from serix.core.config_loader import SerixFileConfig, load_config
from serix.core.target import (
    DecoratorTarget,
    HttpTarget,
    ScriptTarget,
    Target,
    TargetResponse,
)
from serix.core.types import (
    FuzzConfig,
    RecordedInteraction,
    RecordingSession,
    SerixConfig,
    SerixMode,
)
from serix.eval import (
    EvaluationResult,
    EvaluationRubric,
    EvaluationScore,
    Evaluator,
    RemediationEngine,
    Severity,
    Vulnerability,
    VulnerabilityCategory,
)
from serix.fuzz.redteam import Attack, AttackResults, RedTeamEngine
from serix.sdk.decorator import Agent, scan

__version__ = _get_version("serix")
__all__ = [
    # SDK (clean user interface)
    "scan",
    "Agent",
    # Targets
    "Target",
    "TargetResponse",
    "ScriptTarget",
    "HttpTarget",
    "DecoratorTarget",
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
    # Evaluation
    "Evaluator",
    "EvaluationResult",
    "EvaluationScore",
    "EvaluationRubric",
    "RemediationEngine",
    "Vulnerability",
    "VulnerabilityCategory",
    "Severity",
]
