"""
Serix v2 - Services

Business logic services that operate on contracts.
Law 3: All services depend on protocols, not concrete classes.
"""

from serix_v2.services.chaos import (
    ChaosConfig,
    ChaosError,
    ChaosInjector,
    ChaosTarget,
    ErrorMutation,
    JsonMutation,
    LatencyMutation,
    Mutation,
)
from serix_v2.services.fuzz import FuzzService
from serix_v2.services.init_service import InitService
from serix_v2.services.regression import RegressionService
from serix_v2.services.status import StatusService, StatusSummary, TargetStatus

__all__ = [
    # Deterministic fuzz testing (serix test --fuzz)
    "FuzzService",
    # Init service (serix init)
    "InitService",
    # Regression service
    "RegressionService",
    # Status query service (serix status)
    "StatusService",
    "StatusSummary",
    "TargetStatus",
    # Probabilistic chaos injection (serix dev --fuzz)
    "ChaosConfig",
    "ChaosError",
    "ChaosInjector",
    "ChaosTarget",
    "Mutation",
    "LatencyMutation",
    "ErrorMutation",
    "JsonMutation",
]
