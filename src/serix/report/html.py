"""HTML report generation for Serix."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from serix.fuzz.redteam import AttackResults


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
