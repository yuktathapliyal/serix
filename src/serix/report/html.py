"""HTML report generation for Serix."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, PackageLoader, select_autoescape

from serix.fuzz.redteam import AttackResults

if TYPE_CHECKING:
    from serix.eval.evaluator import EvaluationResult
    from serix.eval.remediation import Remediation
    from serix.fuzz.adversary import AdversaryResult
    from serix.heal.types import HealingResult


@dataclass
class OWASPReportData:
    """OWASP vulnerability data for the report."""

    code: str  # e.g., "LLM01"
    name: str  # e.g., "Prompt Injection"
    severity: str  # e.g., "CRITICAL"
    description: str
    url: str = ""


@dataclass
class ToolFixReportData:
    """Data for a tool fix recommendation in the report."""

    recommendation: str
    severity: str  # "required", "recommended", "optional"
    owasp_code: str


@dataclass
class HealingReportData:
    """Data for the Self-Healing proposal in the report."""

    vulnerability_type: str
    owasp_code: str
    confidence: int  # 0-100 percentage
    reasoning: str

    # Text fix (patched prompt)
    has_text_fix: bool = False
    text_fix_diff: str = ""
    text_fix_explanation: str = ""
    patched_prompt: str = ""  # Full patched prompt for copy button

    # Tool fixes
    tool_fixes: list[ToolFixReportData] = field(default_factory=list)


@dataclass
class AttackReportData:
    """Data for a single attack in the report."""

    strategy: str
    payload: str
    response: str | None
    success: bool
    judge_reasoning: str | None = None
    owasp: OWASPReportData | None = None
    healing: HealingReportData | None = None


@dataclass
class HTMLReportData:
    """Data structure for the HTML report."""

    # Metadata
    generated_at: str
    script_path: str
    goal: str
    judge_model: str | None = None

    # Overall status
    overall_status: str = "PASSED"  # "PASSED" or "FAILED"
    status_message: str = ""

    # Stats
    total_attacks: int = 0
    successful_attacks: int = 0
    defended_attacks: int = 0
    exploit_rate: float = 0.0

    # Attacks
    attacks: list[AttackReportData] = field(default_factory=list)

    # Strategy breakdown
    strategy_breakdown: dict[str, dict[str, Any]] = field(default_factory=dict)

    # OWASP data for vulnerabilities
    owasp_vulnerabilities: list[OWASPReportData] = field(default_factory=list)

    healing: HealingReportData | None = None

    # v0.2.6 test configuration metadata
    attacker_model: str | None = None
    critic_model: str | None = None
    serix_version: str | None = None
    test_duration_seconds: float | None = None
    depth: int | None = None
    mode: str | None = None  # "static" or "adaptive"


def create_report_data(
    results: AttackResults,
    script_path: str,
    judge_model: str | None = None,
    vulnerability_type: str = "jailbreak",
) -> HTMLReportData:
    """Convert AttackResults to HTMLReportData with OWASP classification."""
    from serix.eval.classifier import get_owasp_info

    total = len(results.attacks)
    successful = len(results.successful_attacks)
    defended = total - successful

    # Get OWASP info for this vulnerability type
    owasp_info = get_owasp_info(vulnerability_type)
    owasp_report_data = None
    if owasp_info:
        owasp_report_data = OWASPReportData(
            code=owasp_info.code,
            name=owasp_info.name,
            severity=owasp_info.severity,
            description=owasp_info.description,
            url=owasp_info.url,
        )

    # Build strategy breakdown
    strategy_breakdown: dict[str, dict[str, Any]] = {}
    for attack in results.attacks:
        if attack.strategy not in strategy_breakdown:
            strategy_breakdown[attack.strategy] = {"count": 0, "exploited": False}
        strategy_breakdown[attack.strategy]["count"] += 1
        if attack.success:
            strategy_breakdown[attack.strategy]["exploited"] = True

    # Create attack report data with OWASP info for successful attacks
    attack_data = [
        AttackReportData(
            strategy=a.strategy,
            payload=a.payload,
            response=a.response,
            success=a.success,
            judge_reasoning=getattr(a, "judge_reasoning", None),
            owasp=owasp_report_data if a.success else None,
        )
        for a in results.attacks
    ]

    # Collect unique OWASP vulnerabilities found
    owasp_vulnerabilities = []
    if owasp_report_data and successful > 0:
        owasp_vulnerabilities.append(owasp_report_data)

    return HTMLReportData(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        script_path=script_path,
        goal=results.goal,
        judge_model=judge_model,
        overall_status="FAILED" if successful > 0 else "PASSED",
        status_message=(
            f"Agent was compromised by {successful} attack(s)"
            if successful > 0
            else f"Agent successfully defended against all {total} attacks"
        ),
        total_attacks=total,
        successful_attacks=successful,
        defended_attacks=defended,
        exploit_rate=(successful / total * 100) if total > 0 else 0,
        attacks=attack_data,
        strategy_breakdown=strategy_breakdown,
        owasp_vulnerabilities=owasp_vulnerabilities,
    )


def generate_html_report(
    results: AttackResults,
    script_path: str,
    output_path: Path,
    judge_model: str | None = None,
    vulnerability_type: str = "jailbreak",
) -> Path:
    """Generate an HTML report from attack results.

    Args:
        results: The attack results to report
        script_path: Path to the script that was tested
        output_path: Where to save the HTML file
        judge_model: Model used for judging (for metadata)
        vulnerability_type: The type of vulnerability being tested

    Returns:
        Path to the generated report
    """
    # Set up Jinja2 environment
    env = Environment(
        loader=PackageLoader("serix.report", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )

    # Load template
    template = env.get_template("report.html")

    # Create report data with OWASP classification
    report_data = create_report_data(
        results, script_path, judge_model, vulnerability_type
    )

    # Render template
    html_content = template.render(report=report_data)

    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content)

    return output_path


# ============================================================================
# Evaluation Report
# ============================================================================


@dataclass
class VulnerabilityReportData:
    """Data for a single vulnerability in the report."""

    type: str
    severity: str
    description: str
    evidence: str
    remediation: str
    owasp: OWASPReportData | None = None


@dataclass
class GoalResult:
    """Result of testing a single goal (for multi-goal reports)."""

    goal: str
    passed: bool
    personas_tried: list[str] = field(default_factory=list)
    successful_persona: str | None = None
    turns_taken: int = 0
    vulnerabilities: list[VulnerabilityReportData] = field(default_factory=list)


@dataclass
class RemediationReportData:
    """Data for a single remediation in the report."""

    title: str
    description: str
    code_example: str | None
    code_highlighted: str | None  # Pre-highlighted HTML
    priority: int
    references: list[str]


@dataclass
class ConversationMessage:
    """Data for a conversation message."""

    role: str  # "attacker" or "agent"
    content: str


@dataclass
class EvaluationReportData:
    """Data structure for evaluation-based HTML report.

    This is the new report format that includes multi-axis scores,
    vulnerability details, and remediation suggestions.
    """

    # Metadata
    generated_at: str
    target: str
    goal: str  # Primary goal (first or failed goal)

    # Status
    passed: bool
    summary: str

    # Scores (0-100)
    overall_score: int
    safety_score: int
    compliance_score: int
    info_leakage_score: int
    role_adherence_score: int

    # Vulnerabilities
    vulnerabilities: list[VulnerabilityReportData] = field(default_factory=list)

    # Conversation history
    conversation: list[ConversationMessage] = field(default_factory=list)

    # Remediations
    remediations: list[RemediationReportData] = field(default_factory=list)

    # Attack metadata
    persona_used: str = ""
    turns_taken: int = 0
    confidence: str = "medium"

    healing: HealingReportData | None = None

    # Campaign summary: all persona attempts
    attempts_log: list[dict] = field(default_factory=list)

    # Multi-goal support
    goals: list[str] = field(default_factory=list)
    goal_results: list[GoalResult] = field(default_factory=list)

    # Report type indicator (for template)
    is_evaluation_report: bool = True

    # v0.2.6 test configuration metadata
    attacker_model: str | None = None
    judge_model: str | None = None
    critic_model: str | None = None
    serix_version: str | None = None
    test_duration_seconds: float | None = None
    depth: int | None = None
    mode: str | None = None  # "static" or "adaptive"


def get_score_color(score: int) -> str:
    """Get CSS color class for a score value.

    Args:
        score: Score value 0-100

    Returns:
        CSS color class name
    """
    if score >= 80:
        return "green"
    elif score >= 60:
        return "yellow"
    elif score >= 40:
        return "orange"
    else:
        return "red"


def convert_healing_to_report_data(
    healing: "HealingResult | None",
) -> HealingReportData | None:
    """Convert HealingResult to HealingReportData for template rendering.

    Args:
        healing: HealingResult from the Self-Healing engine

    Returns:
        HealingReportData for Jinja2 template, or None if no healing
    """
    if not healing:
        return None

    # Convert tool fixes
    tool_fixes_data = [
        ToolFixReportData(
            recommendation=fix.recommendation,
            severity=fix.severity,
            owasp_code=fix.owasp_code,
        )
        for fix in healing.tool_fixes
    ]

    # Build report data
    return HealingReportData(
        vulnerability_type=healing.vulnerability_type,
        owasp_code=healing.owasp_code,
        confidence=int(healing.confidence * 100),
        reasoning=healing.reasoning,
        has_text_fix=healing.text_fix is not None,
        text_fix_diff=healing.text_fix.diff if healing.text_fix else "",
        text_fix_explanation=healing.text_fix.explanation if healing.text_fix else "",
        patched_prompt=healing.text_fix.patched if healing.text_fix else "",
        tool_fixes=tool_fixes_data,
    )


def highlight_python_code(code: str) -> str:
    """Apply inline CSS syntax highlighting to Python code.

    Args:
        code: Python code string

    Returns:
        HTML string with syntax highlighting spans
    """
    if not code:
        return ""

    # First escape HTML entities
    code = html.escape(code)

    # Define patterns - order matters!
    # Strings (must come first to avoid keyword matching inside strings)
    code = re.sub(
        r"(&quot;&quot;&quot;[\s\S]*?&quot;&quot;&quot;|&#x27;&#x27;&#x27;[\s\S]*?&#x27;&#x27;&#x27;|&quot;[^&]*?&quot;|&#x27;[^&]*?&#x27;)",
        r'<span class="hl-string">\1</span>',
        code,
    )

    # Comments (after strings to avoid matching # inside strings)
    code = re.sub(
        r"(#[^\n]*)",
        r'<span class="hl-comment">\1</span>',
        code,
    )

    # Keywords
    keywords = (
        r"\b(def|class|if|else|elif|return|import|from|for|while|try|except|"
        r"with|as|None|True|False|and|or|not|in|is|async|await|raise|finally|"
        r"lambda|yield|global|nonlocal|pass|break|continue|del|assert)\b"
    )
    code = re.sub(keywords, r'<span class="hl-keyword">\1</span>', code)

    # Decorators
    code = re.sub(r"(@\w+)", r'<span class="hl-decorator">\1</span>', code)

    # Function calls (word followed by parenthesis)
    code = re.sub(
        r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
        r'<span class="hl-function">\1</span>(',
        code,
    )

    return code


def create_evaluation_report_data(
    evaluation: "EvaluationResult",
    adversary_result: "AdversaryResult",
    target: str,
    remediations: list["Remediation"] | None = None,
    goal_results: list[GoalResult] | None = None,
) -> EvaluationReportData:
    """Convert EvaluationResult to EvaluationReportData.

    Args:
        evaluation: EvaluationResult from the evaluator
        adversary_result: AdversaryResult from the attack
        target: Target identifier string
        remediations: Optional list of Remediation objects
        goal_results: Optional list of GoalResult for multi-goal reports

    Returns:
        EvaluationReportData for template rendering
    """
    from serix.eval.classifier import get_owasp_info

    # Convert vulnerabilities with OWASP info
    vuln_data = []
    for v in evaluation.vulnerabilities:
        owasp_info = get_owasp_info(v.type)
        owasp_report_data = None
        if owasp_info:
            owasp_report_data = OWASPReportData(
                code=owasp_info.code,
                name=owasp_info.name,
                severity=owasp_info.severity,
                description=owasp_info.description,
                url=owasp_info.url,
            )
        vuln_data.append(
            VulnerabilityReportData(
                type=v.type,
                severity=v.severity,
                description=v.description,
                evidence=v.evidence,
                remediation=v.remediation,
                owasp=owasp_report_data,
            )
        )

    # Convert conversation
    conv_data = [
        ConversationMessage(
            role=msg.get("role", "unknown"),
            content=msg.get("content", ""),
        )
        for msg in adversary_result.conversation
    ]

    # Convert remediations with syntax highlighting
    rem_data = []
    if remediations:
        for r in remediations:
            rem_data.append(
                RemediationReportData(
                    title=r.title,
                    description=r.description,
                    code_example=r.code_example,
                    code_highlighted=(
                        highlight_python_code(r.code_example)
                        if r.code_example
                        else None
                    ),
                    priority=r.priority,
                    references=r.references,
                )
            )

    # Extract healing data if available
    healing_data = convert_healing_to_report_data(
        getattr(adversary_result, "healing", None)
    )

    # Extract goals list from goal_results if available
    goals_list = [gr.goal for gr in goal_results] if goal_results else []

    return EvaluationReportData(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=target,
        goal=evaluation.metadata.get("goal", ""),
        passed=evaluation.passed,
        summary=evaluation.summary,
        overall_score=evaluation.scores.overall,
        safety_score=evaluation.scores.safety,
        compliance_score=evaluation.scores.compliance,
        info_leakage_score=evaluation.scores.information_leakage,
        role_adherence_score=evaluation.scores.role_adherence,
        vulnerabilities=vuln_data,
        conversation=conv_data,
        remediations=rem_data,
        persona_used=adversary_result.persona_used,
        turns_taken=adversary_result.turns_taken,
        confidence=adversary_result.confidence,
        healing=healing_data,
        attempts_log=getattr(adversary_result, "attempts_log", []),
        goals=goals_list,
        goal_results=goal_results or [],
    )


def generate_evaluation_report(
    evaluation: "EvaluationResult",
    adversary_result: "AdversaryResult",
    target: str,
    output_path: Path,
    remediations: list["Remediation"] | None = None,
    goal_results: list[GoalResult] | None = None,
) -> Path:
    """Generate an HTML report from evaluation results.

    Args:
        evaluation: EvaluationResult from the evaluator
        adversary_result: AdversaryResult from the attack
        target: Target identifier string
        output_path: Where to save the HTML file
        remediations: Optional list of Remediation objects
        goal_results: Optional list of GoalResult for multi-goal reports

    Returns:
        Path to the generated report
    """
    # Set up Jinja2 environment
    env = Environment(
        loader=PackageLoader("serix.report", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )

    # Add custom filters
    env.filters["score_color"] = get_score_color

    # Load template
    template = env.get_template("report.html")

    # Create report data
    report_data = create_evaluation_report_data(
        evaluation, adversary_result, target, remediations, goal_results
    )

    # Render template
    html_content = template.render(report=report_data)

    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content)

    return output_path
