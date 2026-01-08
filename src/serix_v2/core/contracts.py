"""
Serix v2 - Data Contracts (The "Bible")

This file is the SINGLE SOURCE OF TRUTH for all data structures that cross
module boundaries. If a data structure is not defined here, it does not exist.

Law 1: No raw dicts between modules. Everything is a Pydantic model.

Reference: Spec 1.16 (JSON Schema), Developer Checklist
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    """Return current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


# ============================================================================
# ENUMS
# ============================================================================


class AttackStatus(str, Enum):
    """Status of an attack in the library."""

    EXPLOITED = "exploited"
    DEFENDED = "defended"


class AttackMode(str, Enum):
    """How attacks are executed."""

    ADAPTIVE = "adaptive"  # Multi-turn with critic feedback
    STATIC = "static"  # Single-shot templates


class Persona(str, Enum):
    """Attack personas (Spec 1.1 --scenarios)."""

    JAILBREAKER = "jailbreaker"
    EXTRACTOR = "extractor"
    CONFUSER = "confuser"
    MANIPULATOR = "manipulator"


class TargetType(str, Enum):
    """Type of target being tested."""

    PYTHON_FUNCTION = "python:function"
    PYTHON_CLASS = "python:class"
    HTTP_ENDPOINT = "http:endpoint"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Grade(str, Enum):
    """Security grade (letter scale)."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    UNKNOWN = "?"  # Used when test was cancelled or couldn't complete


class ProgressPhase(str, Enum):
    """Phase of campaign execution for progress reporting."""

    PREFLIGHT = "preflight"
    REGRESSION = "regression"
    ATTACKS = "attacks"
    FUZZ = "fuzz"
    COMPLETE = "complete"


# ============================================================================
# MODEL OUTPUTS (What LLM-powered components return)
# ============================================================================


class CriticFeedback(BaseModel):
    """
    Output from the Critic model (per-turn coaching).

    The Critic does NOT determine exploitation - that's the Judge's job.
    The Critic advises whether to continue and how to pivot.
    """

    should_continue: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    suggested_pivot: Optional[str] = None


class JudgeVerdict(BaseModel):
    """
    Output from the Judge model (final verdict).

    The Judge determines if an attack succeeded (EXPLOITED) or failed (DEFENDED).
    """

    verdict: AttackStatus
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class VulnerabilityAnalysis(BaseModel):
    """
    Output from the Analyzer model (OWASP mapping & root cause).
    """

    vulnerability_type: str  # e.g., "jailbreak", "data_extraction"
    owasp_code: str  # e.g., "LLM01", "LLM06"
    severity: Severity
    root_cause: str


class HealingPatch(BaseModel):
    """
    A text-based fix (system prompt patch).
    """

    original: str
    patched: str
    diff: str
    explanation: str


class ToolRecommendation(BaseModel):
    """
    A policy/tooling recommendation.
    """

    recommendation: str
    severity: str  # "required", "recommended", "optional"
    owasp_code: str


class HealingResult(BaseModel):
    """
    Output from the Patcher model (healing/fix generation).
    """

    patch: Optional[HealingPatch] = None
    recommendations: list[ToolRecommendation] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


# ============================================================================
# REGRESSION (Phase 5 - Immune Check)
# ============================================================================


class AttackTransition(BaseModel):
    """
    Tracks a single attack's state transition during regression check.

    The "Delta" that CISOs care about:
    - "Last run: Exploited. This run: Defended" = Fixed!
    - "Last run: Defended. This run: Exploited" = Regression!

    Phase 11: Added response + verdict fields for transcript capture.
    Phase 12O: Added owasp_code + exploited_since for findings display.
    """

    attack_id: str
    goal: str
    strategy_id: str
    payload: str
    previous_status: AttackStatus
    current_status: AttackStatus

    # Phase 11: Capture evidence for report transparency
    response: Optional[str] = None  # Target's response during replay
    verdict_reasoning: Optional[str] = None  # Judge's explanation
    verdict_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    # Phase 12O: For findings display and deduplication
    owasp_code: Optional[str] = None  # Copy from StoredAttack
    exploited_since: Optional[datetime] = None  # Streak tracking for lifecycle

    @property
    def is_still_defended(self) -> bool:
        """True if defended both times (no security delta - not interesting)."""
        return (
            self.previous_status == AttackStatus.DEFENDED
            and self.current_status == AttackStatus.DEFENDED
        )

    @property
    def is_regression(self) -> bool:
        """True if previously defended but now exploited."""
        return (
            self.previous_status == AttackStatus.DEFENDED
            and self.current_status == AttackStatus.EXPLOITED
        )

    @property
    def is_fixed(self) -> bool:
        """True if previously exploited but now defended."""
        return (
            self.previous_status == AttackStatus.EXPLOITED
            and self.current_status == AttackStatus.DEFENDED
        )


class RegressionResult(BaseModel):
    """
    Complete result of a regression check.

    Founder's Tip: Focus on the DELTA - Before vs. After.
    """

    replayed: int = 0
    still_exploited: int = 0
    now_defended: int = 0
    regressions: int = 0
    transitions: list[AttackTransition] = Field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        """True if any previously defended attacks are now exploited."""
        return self.regressions > 0

    @property
    def all_fixed(self) -> bool:
        """True if all replayed attacks are now defended."""
        return self.still_exploited == 0 and self.replayed > 0


# ============================================================================
# SCORING (Evaluator output)
# ============================================================================


class ScoreAxis(BaseModel):
    """A single axis in the multi-axis security score."""

    name: str  # e.g., "Safety", "Compliance", "Info Leak", "Role"
    score: int  # 0-100
    verdict: str  # Brief explanation


class SecurityScore(BaseModel):
    """
    Aggregated security score across all axes.
    """

    overall_score: int = Field(ge=0, le=100)
    grade: Grade
    axes: list[ScoreAxis] = Field(default_factory=list)


# ============================================================================
# EXECUTION UNITS (The atoms of a test run)
# ============================================================================


class AttackTurn(BaseModel):
    """
    A single turn in an attack conversation.

    Turn = Attacker sends payload -> Target responds -> Critic evaluates
    """

    turn_number: int
    payload: str  # What attacker sent
    response: str  # What target returned
    critic_feedback: Optional[CriticFeedback] = None
    latency_ms: float = 0.0
    # FH-01: Structured error tracking for report highlighting
    # Populated with exception class name (e.g., "ValueError", "TimeoutError")
    # None when target call succeeds
    error_type: Optional[str] = None


class AttackResult(BaseModel):
    """
    Result of running a single attack (one persona + one goal).

    This is the TRANSIENT result during execution.
    For persistence, see StoredAttack.
    """

    goal: str
    persona: Persona
    success: bool
    turns: list[AttackTurn]
    judge_verdict: Optional[JudgeVerdict] = None
    analysis: Optional[VulnerabilityAnalysis] = None
    healing: Optional[HealingResult] = None
    # FH-02: Support multiple winning payloads for exhaustive mode
    # All payloads that caused EXPLOITED verdict are captured
    winning_payloads: list[str] = Field(default_factory=list)

    @property
    def winning_payload(self) -> Optional[str]:
        """First winning payload (backwards compatible property)."""
        return self.winning_payloads[0] if self.winning_payloads else None


class ResilienceResult(BaseModel):
    """
    Result of a single resilience/fuzz test.
    """

    test_type: str  # "latency", "http_500", "http_503", "http_429", "json_corruption"
    passed: bool
    details: str
    latency_ms: float = 0.0


# ============================================================================
# CAMPAIGN RESULT (The aggregate of a full test run)
# ============================================================================


class CampaignResult(BaseModel):
    """
    Complete result of a 'serix test' execution.

    This is what gets serialized to results.json in the campaign folder.
    Reference: Spec 1.16

    NOTE: regression_* fields must ONLY be set by RegressionService.
    """

    # Identity
    run_id: str
    target_id: str
    serix_version: str = "0.3.0"
    schema_version: str = "1.0"
    timestamp: datetime = Field(default_factory=_utc_now)

    # Target info
    target_locator: str  # e.g., "agent.py:my_agent"
    target_type: TargetType
    target_name: Optional[str] = None

    # Summary
    passed: bool  # True if all attacks defended
    duration_seconds: float = 0.0

    # Results
    score: SecurityScore
    attacks: list[AttackResult] = Field(default_factory=list)
    resilience: list[ResilienceResult] = Field(default_factory=list)

    # Regression context (SET ONLY BY RegressionService)
    regression_ran: bool = False
    regression_replayed: int = 0
    regression_still_exploited: int = 0
    regression_now_defended: int = 0
    regression_transitions: list[AttackTransition] = Field(default_factory=list)

    # Aggregated patches from all successful attacks (unified diff format)
    aggregated_patch: Optional[str] = None


# ============================================================================
# STORED ATTACK (For attack library persistence - Spec 1.15)
# ============================================================================


class StoredAttack(BaseModel):
    """
    An attack stored in the attack library (.serix/targets/<id>/attacks.json).

    Dedup key: (target_id, goal, strategy_id)

    Reference: Spec 1.4, Spec 1.15
    """

    id: str  # UUID
    target_id: str
    goal: str
    strategy_id: str  # Persona name
    payload: str  # The winning payload
    status: AttackStatus
    owasp_code: Optional[str] = None
    created_at: datetime = Field(default_factory=_utc_now)
    last_tested: datetime = Field(default_factory=_utc_now)
    exploited_since: Optional[datetime] = None  # Streak tracking for lifecycle


class AttackLibrary(BaseModel):
    """
    The complete attack library for a target.

    Stored at: .serix/targets/<target_id>/attacks.json
    """

    schema_version: int = 1
    target_id: str
    attacks: list[StoredAttack] = Field(default_factory=list)


# ============================================================================
# TARGET METADATA (For target tracking - Spec 1.3)
# ============================================================================


class TargetMetadata(BaseModel):
    """
    Metadata about a target.

    Stored at: .serix/targets/<target_id>/metadata.json
    """

    schema_version: int = 1
    target_id: str
    target_type: TargetType
    locator: str  # e.g., "src/agent.py:my_agent"
    name: Optional[str] = None  # Alias from --name
    created_at: datetime = Field(default_factory=_utc_now)


# ============================================================================
# INDEX (For alias -> target_id mapping - Spec 1.3)
# ============================================================================


class TargetIndex(BaseModel):
    """
    Global index mapping aliases to target IDs.

    Stored at: .serix/index.json
    """

    schema_version: int = 1
    aliases: dict[str, str] = Field(default_factory=dict)  # alias -> target_id


# ============================================================================
# CAMPAIGN RUN METADATA (For run config persistence - Spec 1.3)
# ============================================================================


class CampaignRunMetadata(BaseModel):
    """
    Run configuration saved alongside campaign results.

    Stored at: .serix/targets/<target_id>/campaigns/<run_id>/metadata.json

    This captures the meaningful test parameters for audit and reproducibility.
    """

    schema_version: int = 1
    run_id: str
    target_id: str
    serix_version: str = "0.3.0"
    timestamp: datetime = Field(default_factory=_utc_now)

    # Test configuration
    mode: AttackMode
    depth: int
    goals: list[str]
    scenarios: list[str]

    # Models used
    attacker_model: str
    judge_model: str
    critic_model: Optional[str] = None
    patcher_model: Optional[str] = None
    analyzer_model: Optional[str] = None

    # Behavioral flags
    exhaustive: bool = False
    skip_regression: bool = False
    fuzz_enabled: bool = False


# ============================================================================
# INIT SERVICE (For serix init command)
# ============================================================================


class InitResult(BaseModel):
    """
    Result of init template generation.

    Used by InitService to return the generated serix.toml template
    along with version metadata.
    """

    template: str
    version: str = "0.3.0"


# ============================================================================
# PROGRESS EVENTS (For live CLI progress display)
# ============================================================================


class ProgressEvent(BaseModel):
    """
    Progress event emitted during campaign execution.

    Law 2 Compliant: This is a plain Pydantic model with no Rich imports.
    The CLI layer handles rendering based on these events.
    """

    phase: ProgressPhase

    # Regression phase
    regression_current: int = 0
    regression_total: int = 0
    regression_now_defended: int = 0
    regression_still_exploited: int = 0

    # Attack phase
    persona: Optional[str] = None
    turn: int = 0
    depth: int = 0
    goal_index: int = 0
    total_goals: int = 0

    # Attack status (for completed attacks)
    attack_complete: bool = False
    attack_success: Optional[bool] = None  # True=exploited, False=defended

    # All personas for display state
    personas: list[str] = Field(default_factory=list)
    completed_personas: dict[str, tuple[bool, int]] = Field(
        default_factory=dict
    )  # persona -> (success, turns)

    # Reasoning feed (from Critic/Attacker for "thinking" display)
    reasoning: Optional[str] = None


# Type alias for progress callback function
ProgressCallback = Callable[[ProgressEvent], None]

# Type alias for confirmation callback (returns True to continue, False to abort)
ConfirmCallback = Callable[["RegressionResult"], bool]
