"""
Serix v2 - Storage Layer

Implements AttackStore and CampaignStore protocols for persisting
attack libraries and campaign results to disk.

Reference: Phase 3A, Spec 1.15, Spec 1.16
"""

from .attack_store import FileAttackStore
from .campaign_store import FileCampaignStore

__all__ = ["FileAttackStore", "FileCampaignStore"]
