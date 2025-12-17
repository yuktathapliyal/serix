"""Fuzzing module - mutations and red team engine."""

from serix.fuzz.adversary import AdversaryLoop, AdversaryResult, CriticFeedback
from serix.fuzz.engine import FuzzEngine, FuzzResult
from serix.fuzz.mutations import (
    ErrorMutation,
    JsonCorruptionMutation,
    LatencyMutation,
    Mutation,
)
from serix.fuzz.redteam import Attack, AttackResults, JudgeVerdict, RedTeamEngine
from serix.fuzz.scenarios import SCENARIOS, Scenario, get_scenario, list_scenarios

__all__ = [
    # Fuzzing
    "FuzzEngine",
    "FuzzResult",
    "Mutation",
    "LatencyMutation",
    "ErrorMutation",
    "JsonCorruptionMutation",
    # Red Team (legacy)
    "RedTeamEngine",
    "Attack",
    "AttackResults",
    "JudgeVerdict",
    # Adversary
    "AdversaryLoop",
    "AdversaryResult",
    "CriticFeedback",
    # Scenarios
    "Scenario",
    "SCENARIOS",
    "get_scenario",
    "list_scenarios",
]
