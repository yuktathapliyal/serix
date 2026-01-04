"""
Serix v2 - JSON Report Schema (Spec 1.16)

Defines the external JSON format for:
- HTML report generation (Phase 10A)
- GitHub Actions output (Phase 10B)
- External tools and CI/CD pipelines

Law 1: No raw dicts - all typed Pydantic models
Law 2: No typer/rich imports in this module
"""

from typing import Optional

from pydantic import BaseModel, Field

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import AttackResult, CampaignResult

# ============================================================================
# NESTED INFO MODELS
# ============================================================================


class TargetInfo(BaseModel):
    """Nested target information in the report."""

    locator: str  # e.g., "src/agents/support.py:respond"
    type: str  # "python:function", "python:class", "http:endpoint"
    name: Optional[str] = None  # Alias from --name


class ModelsInfo(BaseModel):
    """LLM models used in the test."""

    attacker: str
    judge: str


class ConfigInfo(BaseModel):
    """
    Meaningful test configuration (excludes internal flags).

    Includes only what a CISO needs to understand the test:
    - mode, depth, goals, scenarios, models

    Excludes internal flags like:
    - verbose, dry_run, yes, headers_file, etc.
    """

    mode: str  # "adaptive" or "static"
    depth: int
    goals: list[str]
    scenarios: list[str]
    models: ModelsInfo


class SummaryInfo(BaseModel):
    """Test run summary statistics."""

    passed: bool
    score: int = Field(ge=0, le=100)  # 0-100
    grade: str  # A, B, C, D, F
    total_attacks: int
    exploited: int
    defended: int
    duration_seconds: float


class VulnerabilityInfo(BaseModel):
    """Single vulnerability extracted from a successful attack."""

    goal: str
    scenario: str  # persona name lowercase
    owasp_code: Optional[str] = None
    severity: str  # "critical", "high", "medium", "low"
    confidence: float


class ConversationTurn(BaseModel):
    """Single turn in attack conversation."""

    role: str  # "attacker" or "target"
    content: str


class PersonaResultInfo(BaseModel):
    """Results from a single persona's attack attempt."""

    persona: str
    goal: str
    success: bool
    turns_taken: int
    confidence: Optional[float] = None
    winning_payloads: list[str] = Field(
        default_factory=list
    )  # ALL payloads (exhaustive mode)
    conversation: list[ConversationTurn] = Field(default_factory=list)


class RecommendationInfo(BaseModel):
    """Security recommendation from healing."""

    severity: str  # "required", "recommended", "optional"
    text: str
    owasp: Optional[str] = None


class HealingInfo(BaseModel):
    """Aggregated healing information."""

    generated: bool
    diff_text: Optional[str] = None  # Actual diff content, not file path
    patched_text: Optional[str] = None  # Full patched prompt for instant copy
    recommendations: list[RecommendationInfo] = Field(default_factory=list)


class RegressionInfo(BaseModel):
    """Regression check results."""

    ran: bool
    total_replayed: int
    still_exploited: int
    now_defended: int


class ResilienceInfo(BaseModel):
    """
    Single resilience/fuzz test result.

    Law 1 compliant: Typed model, not raw dict.
    """

    test_type: str  # "latency", "http_500", "http_503", "http_429", "json_corruption"
    passed: bool
    details: str
    latency_ms: float


# ============================================================================
# TOP-LEVEL SCHEMA
# ============================================================================


class JSONReportSchema(BaseModel):
    """
    Spec 1.16 compliant JSON report format.

    This is the external format consumed by:
    - HTML report generation (Phase 10A)
    - GitHub Actions output (Phase 10B)
    - External tools and CI/CD pipelines
    """

    version: str = "1.1"  # Schema version
    serix_version: str
    timestamp: str  # ISO format
    run_id: str
    target_id: str

    target: TargetInfo
    config: Optional[ConfigInfo] = None  # Included when config passed to transform
    summary: SummaryInfo
    vulnerabilities: list[VulnerabilityInfo] = Field(default_factory=list)
    persona_results: list[PersonaResultInfo] = Field(default_factory=list)
    healing: HealingInfo
    regression: RegressionInfo
    resilience: list[ResilienceInfo] = Field(default_factory=list)


# ============================================================================
# TRANSFORM FUNCTION
# ============================================================================


def _flatten_conversation(attack: AttackResult) -> list[ConversationTurn]:
    """
    Flatten AttackTurn list into {role, content} pairs.

    Each turn becomes two ConversationTurn items:
    1. attacker -> turn.payload
    2. target -> turn.response
    """
    conversation: list[ConversationTurn] = []
    for turn in attack.turns:
        conversation.append(ConversationTurn(role="attacker", content=turn.payload))
        conversation.append(ConversationTurn(role="target", content=turn.response))
    return conversation


def _extract_vulnerabilities(attacks: list[AttackResult]) -> list[VulnerabilityInfo]:
    """
    Extract vulnerabilities from successful attacks only.

    Each successful attack becomes one VulnerabilityInfo.
    """
    vulnerabilities: list[VulnerabilityInfo] = []
    for attack in attacks:
        if attack.success and attack.judge_verdict:
            owasp_code = None
            severity = "high"  # Default if no analysis

            if attack.analysis:
                owasp_code = attack.analysis.owasp_code
                severity = attack.analysis.severity.value

            vulnerabilities.append(
                VulnerabilityInfo(
                    goal=attack.goal,
                    scenario=attack.persona.value,
                    owasp_code=owasp_code,
                    severity=severity,
                    confidence=attack.judge_verdict.confidence,
                )
            )
    return vulnerabilities


def _transform_persona_results(attacks: list[AttackResult]) -> list[PersonaResultInfo]:
    """Transform AttackResult list to PersonaResultInfo list."""
    results: list[PersonaResultInfo] = []
    for attack in attacks:
        confidence = attack.judge_verdict.confidence if attack.judge_verdict else None
        results.append(
            PersonaResultInfo(
                persona=attack.persona.value,
                goal=attack.goal,
                success=attack.success,
                turns_taken=len(attack.turns),
                confidence=confidence,
                winning_payloads=attack.winning_payloads,  # Already a list
                conversation=_flatten_conversation(attack),
            )
        )
    return results


def _aggregate_healing(attacks: list[AttackResult]) -> HealingInfo:
    """
    Aggregate healing information from all attacks.

    - generated: True if any attack has healing
    - diff_text: First available diff (or None)
    - patched_text: Full patched prompt for instant copy
    - recommendations: Deduplicated by OWASP code
    """
    generated = False
    diff_text: Optional[str] = None
    patched_text: Optional[str] = None
    seen_owasp: set[Optional[str]] = set()
    recommendations: list[RecommendationInfo] = []

    for attack in attacks:
        if attack.healing:
            generated = True

            # Take first available diff and patched text
            if diff_text is None and attack.healing.patch:
                diff_text = attack.healing.patch.diff
                patched_text = attack.healing.patch.patched

            # Deduplicate recommendations by OWASP code
            for rec in attack.healing.recommendations:
                if rec.owasp_code not in seen_owasp:
                    seen_owasp.add(rec.owasp_code)
                    recommendations.append(
                        RecommendationInfo(
                            severity=rec.severity,
                            text=rec.recommendation,
                            owasp=rec.owasp_code,
                        )
                    )

    return HealingInfo(
        generated=generated,
        diff_text=diff_text,
        patched_text=patched_text,
        recommendations=recommendations,
    )


def _transform_resilience(campaign: CampaignResult) -> list[ResilienceInfo]:
    """Transform ResilienceResult list to ResilienceInfo list."""
    return [
        ResilienceInfo(
            test_type=r.test_type,
            passed=r.passed,
            details=r.details,
            latency_ms=r.latency_ms,
        )
        for r in campaign.resilience
    ]


def _build_config_info(config: SerixSessionConfig) -> ConfigInfo:
    """
    Build ConfigInfo from SerixSessionConfig.

    Only includes meaningful fields:
    - mode, depth, goals, scenarios, models

    Excludes internal flags like verbose, dry_run, etc.
    """
    return ConfigInfo(
        mode=config.mode.value,
        depth=config.depth,
        goals=config.goals,
        scenarios=config.scenarios,
        models=ModelsInfo(
            attacker=config.attacker_model,
            judge=config.judge_model,
        ),
    )


def transform_campaign_result(
    campaign: CampaignResult,
    config: Optional[SerixSessionConfig] = None,
) -> JSONReportSchema:
    """
    Transform internal CampaignResult to Spec 1.16 JSON format.

    Args:
        campaign: Internal campaign result from TestWorkflow
        config: Optional session config for including test parameters
                (only meaningful fields are extracted, not internal flags)

    Returns:
        JSONReportSchema ready for serialization

    Example:
        result = workflow.run(...)
        report = transform_campaign_result(result, config)
        json_str = report.model_dump_json(indent=2)
    """
    # Count exploited/defended
    exploited_count = sum(1 for a in campaign.attacks if a.success)
    defended_count = len(campaign.attacks) - exploited_count

    return JSONReportSchema(
        version="1.1",
        serix_version=campaign.serix_version,
        timestamp=campaign.timestamp.isoformat(),
        run_id=campaign.run_id,
        target_id=campaign.target_id,
        target=TargetInfo(
            locator=campaign.target_locator,
            type=campaign.target_type.value,
            name=campaign.target_name,
        ),
        config=_build_config_info(config) if config else None,
        summary=SummaryInfo(
            passed=campaign.passed,
            score=campaign.score.overall_score,
            grade=campaign.score.grade.value,
            total_attacks=len(campaign.attacks),
            exploited=exploited_count,
            defended=defended_count,
            duration_seconds=campaign.duration_seconds,
        ),
        vulnerabilities=_extract_vulnerabilities(campaign.attacks),
        persona_results=_transform_persona_results(campaign.attacks),
        healing=_aggregate_healing(campaign.attacks),
        regression=RegressionInfo(
            ran=campaign.regression_ran,
            total_replayed=campaign.regression_replayed,
            still_exploited=campaign.regression_still_exploited,
            now_defended=campaign.regression_now_defended,
        ),
        resilience=_transform_resilience(campaign),
    )
