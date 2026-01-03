"""
Serix v2 - Report Module

Provides JSON report schema and transformation from internal CampaignResult
to external Spec 1.16 compliant format.

This module is consumed by:
- HTML report generation (Phase 10A)
- GitHub Actions output (Phase 10B)
- External tools and CI/CD pipelines
"""

from .schema import (
    ConfigInfo,
    ConversationTurn,
    HealingInfo,
    JSONReportSchema,
    ModelsInfo,
    PersonaResultInfo,
    RecommendationInfo,
    RegressionInfo,
    ResilienceInfo,
    SummaryInfo,
    TargetInfo,
    VulnerabilityInfo,
    transform_campaign_result,
)

__all__ = [
    # Models
    "TargetInfo",
    "ModelsInfo",
    "ConfigInfo",
    "SummaryInfo",
    "VulnerabilityInfo",
    "ConversationTurn",
    "PersonaResultInfo",
    "RecommendationInfo",
    "HealingInfo",
    "RegressionInfo",
    "ResilienceInfo",
    "JSONReportSchema",
    # Transform function
    "transform_campaign_result",
]
