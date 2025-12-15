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


@dataclass
class AttackReportData:
    """Data for a single attack in the report."""

    strategy: str
    payload: str
    response: str | None
    success: bool
    judge_reasoning: str | None = None


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


def create_report_data(
    results: AttackResults,
    script_path: str,
    judge_model: str | None = None,
) -> HTMLReportData:
    """Convert AttackResults to HTMLReportData."""
    total = len(results.attacks)
    successful = len(results.successful_attacks)
    defended = total - successful

    # Build strategy breakdown
    strategy_breakdown: dict[str, dict[str, Any]] = {}
    for attack in results.attacks:
        if attack.strategy not in strategy_breakdown:
            strategy_breakdown[attack.strategy] = {"count": 0, "exploited": False}
        strategy_breakdown[attack.strategy]["count"] += 1
        if attack.success:
            strategy_breakdown[attack.strategy]["exploited"] = True

    # Create attack report data
    attack_data = [
        AttackReportData(
            strategy=a.strategy,
            payload=a.payload,
            response=a.response,
            success=a.success,
            judge_reasoning=getattr(a, "judge_reasoning", None),
        )
        for a in results.attacks
    ]

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
    )


def generate_html_report(
    results: AttackResults,
    script_path: str,
    output_path: Path,
    judge_model: str | None = None,
) -> Path:
    """Generate an HTML report from attack results.

    Args:
        results: The attack results to report
        script_path: Path to the script that was tested
        output_path: Where to save the HTML file
        judge_model: Model used for judging (for metadata)

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

    # Create report data
    report_data = create_report_data(results, script_path, judge_model)

    # Render template
    html_content = template.render(report=report_data)

    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content)

    return output_path


# ============================================================================
# Evaluation Report (Module 3+)
# ============================================================================


@dataclass
class VulnerabilityReportData:
    """Data for a single vulnerability in the report."""

    type: str
    severity: str
    description: str
    evidence: str
    remediation: str


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
    goal: str

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

    # Report type indicator (for template)
    is_evaluation_report: bool = True


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
) -> EvaluationReportData:
    """Convert EvaluationResult to EvaluationReportData.

    Args:
        evaluation: EvaluationResult from the evaluator
        adversary_result: AdversaryResult from the attack
        target: Target identifier string
        remediations: Optional list of Remediation objects

    Returns:
        EvaluationReportData for template rendering
    """
    # Convert vulnerabilities
    vuln_data = [
        VulnerabilityReportData(
            type=v.type,
            severity=v.severity,
            description=v.description,
            evidence=v.evidence,
            remediation=v.remediation,
        )
        for v in evaluation.vulnerabilities
    ]

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
    )


def generate_evaluation_report(
    evaluation: "EvaluationResult",
    adversary_result: "AdversaryResult",
    target: str,
    output_path: Path,
    remediations: list["Remediation"] | None = None,
) -> Path:
    """Generate an HTML report from evaluation results.

    Args:
        evaluation: EvaluationResult from the evaluator
        adversary_result: AdversaryResult from the attack
        target: Target identifier string
        output_path: Where to save the HTML file
        remediations: Optional list of Remediation objects

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
        evaluation, adversary_result, target, remediations
    )

    # Render template
    html_content = template.render(report=report_data)

    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content)

    return output_path
