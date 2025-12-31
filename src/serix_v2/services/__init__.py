"""
Serix v2 - Services

Business logic services that operate on contracts.
Law 3: All services depend on protocols, not concrete classes.
"""

from serix_v2.services.regression import RegressionService

__all__ = ["RegressionService"]
