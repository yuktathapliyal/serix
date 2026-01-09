"""
Serix v2 - Report Module

Provides:
- JSON report schema and transformation (Phase 9A)
- HTML report generation (Phase 10A)
- GitHub Actions output (Phase 10B)

This module is consumed by:
- CLI commands (serix test --report)
- GitHub Actions output (Phase 10B)
- External tools and CI/CD pipelines
"""

from .github import (
    GitHubOutput,
    GitHubOutputFormatter,
    is_github_actions,
    write_github_output,
)
from .html import (
    HTMLReportGenerator,
    escape_html,
    format_diff,
    format_duration,
    get_grade_color,
    get_score_color,
    get_severity_color,
    smart_truncate,
    write_html_report,
)
from .schema import (
    ConfigInfo,
    ConversationTurn,
    HealingInfo,
    JSONReportSchema,
    ModelsInfo,
    PersonaResultInfo,
    RecommendationInfo,
    RegressionInfo,
    RegressionTransitionInfo,
    ResilienceInfo,
    SummaryInfo,
    TargetInfo,
    VulnerabilityInfo,
    transform_campaign_result,
)

__all__ = [
    # Schema Models
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
    "RegressionTransitionInfo",
    "ResilienceInfo",
    "JSONReportSchema",
    # Transform function
    "transform_campaign_result",
    # HTML Report (Phase 10A)
    "HTMLReportGenerator",
    "write_html_report",
    # GitHub Actions Output (Phase 10B)
    "GitHubOutput",
    "GitHubOutputFormatter",
    "write_github_output",
    "is_github_actions",
    # Jinja2 Filters (exposed for custom templates)
    "get_score_color",
    "get_severity_color",
    "get_grade_color",
    "format_duration",
    "format_diff",
    "smart_truncate",
    "escape_html",
]
