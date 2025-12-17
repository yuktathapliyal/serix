"""GitHub Actions integration for Serix reports."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from serix.eval.evaluator import EvaluationResult


def get_score_emoji(score: int) -> str:
    """Get emoji indicator for a score value.

    Args:
        score: Score value 0-100

    Returns:
        Emoji string
    """
    if score >= 80:
        return ":white_check_mark:"
    elif score >= 60:
        return ":yellow_circle:"
    elif score >= 40:
        return ":orange_circle:"
    else:
        return ":red_circle:"


def generate_pr_comment(
    evaluation: "EvaluationResult",
    target: str,
) -> str:
    """Generate markdown content for a GitHub PR comment.

    Args:
        evaluation: EvaluationResult from the evaluator
        target: Target identifier string

    Returns:
        Markdown string for PR comment
    """
    status = "PASSED" if evaluation.passed else "FAILED"
    status_emoji = ":white_check_mark:" if evaluation.passed else ":x:"

    lines = [
        "## Serix Security Scan Results",
        "",
        f"**Status:** {status_emoji} {status}",
        f"**Target:** `{target}`",
        "",
    ]

    # Scores table
    lines.extend(
        [
            "### Security Scores",
            "",
            "| Axis | Score | Status |",
            "|------|-------|--------|",
            f"| **Overall** | {evaluation.scores.overall}/100 | {get_score_emoji(evaluation.scores.overall)} |",
            f"| Safety | {evaluation.scores.safety}/100 | {get_score_emoji(evaluation.scores.safety)} |",
            f"| Compliance | {evaluation.scores.compliance}/100 | {get_score_emoji(evaluation.scores.compliance)} |",
            f"| Info Leakage | {evaluation.scores.information_leakage}/100 | {get_score_emoji(evaluation.scores.information_leakage)} |",
            f"| Role Adherence | {evaluation.scores.role_adherence}/100 | {get_score_emoji(evaluation.scores.role_adherence)} |",
            "",
        ]
    )

    # Vulnerabilities section
    if evaluation.vulnerabilities:
        lines.extend(
            [
                "### Vulnerabilities Found",
                "",
            ]
        )

        for vuln in evaluation.vulnerabilities:
            severity_emoji = {
                "critical": ":red_circle:",
                "high": ":orange_circle:",
                "medium": ":yellow_circle:",
                "low": ":large_blue_circle:",
            }.get(vuln.severity, ":white_circle:")

            lines.append(
                f"- {severity_emoji} **{vuln.severity.upper()}** `{vuln.type}`: {vuln.description}"
            )

        lines.append("")

        # Remediations in collapsible section
        lines.extend(
            [
                "<details>",
                "<summary>View Recommended Remediations</summary>",
                "",
            ]
        )

        seen_types = set()
        for vuln in evaluation.vulnerabilities:
            if vuln.type not in seen_types and vuln.remediation:
                seen_types.add(vuln.type)
                lines.extend(
                    [
                        f"#### {vuln.type}",
                        "",
                        vuln.remediation[:500]
                        + ("..." if len(vuln.remediation) > 500 else ""),
                        "",
                    ]
                )

        lines.extend(
            [
                "</details>",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "### No Vulnerabilities Found :tada:",
                "",
                "The agent successfully defended against all attack scenarios.",
                "",
            ]
        )

    # Metadata
    lines.extend(
        [
            "---",
            f"*Persona: {evaluation.metadata.get('persona_used', 'N/A')} | "
            f"Turns: {evaluation.metadata.get('turns_taken', 'N/A')} | "
            f"Confidence: {evaluation.metadata.get('confidence', 'N/A')}*",
        ]
    )

    return "\n".join(lines)


def generate_github_summary(
    evaluation: "EvaluationResult",
    target: str | None = None,
) -> str:
    """Generate markdown for GITHUB_STEP_SUMMARY.

    This is a more concise version suitable for the Actions summary.

    Args:
        evaluation: EvaluationResult from the evaluator
        target: Optional target identifier

    Returns:
        Markdown string for step summary
    """
    status = "PASSED" if evaluation.passed else "FAILED"
    status_emoji = ":white_check_mark:" if evaluation.passed else ":x:"

    lines = [
        "# Serix Security Scan",
        "",
        f"## {status_emoji} {status}",
        "",
    ]

    if target:
        lines.append(f"**Target:** `{target}`")
        lines.append("")

    # Score summary
    lines.extend(
        [
            "| Metric | Score |",
            "|--------|-------|",
            f"| Overall | **{evaluation.scores.overall}**/100 |",
            f"| Safety | {evaluation.scores.safety}/100 |",
            f"| Compliance | {evaluation.scores.compliance}/100 |",
            f"| Info Leakage | {evaluation.scores.information_leakage}/100 |",
            f"| Role Adherence | {evaluation.scores.role_adherence}/100 |",
            "",
        ]
    )

    # Vulnerability count
    vuln_count = len(evaluation.vulnerabilities)
    if vuln_count > 0:
        critical = sum(
            1 for v in evaluation.vulnerabilities if v.severity == "critical"
        )
        high = sum(1 for v in evaluation.vulnerabilities if v.severity == "high")

        lines.append(f"**Vulnerabilities:** {vuln_count} found")
        if critical > 0:
            lines.append(f"- :red_circle: {critical} critical")
        if high > 0:
            lines.append(f"- :orange_circle: {high} high")
    else:
        lines.append("**Vulnerabilities:** None found :tada:")

    return "\n".join(lines)


def write_github_output(
    evaluation: "EvaluationResult",
    target: str | None = None,
) -> bool:
    """Write outputs to GITHUB_OUTPUT and GITHUB_STEP_SUMMARY.

    This function automatically detects if running in GitHub Actions
    and writes the appropriate files.

    Args:
        evaluation: EvaluationResult from the evaluator
        target: Optional target identifier

    Returns:
        True if outputs were written, False if not in CI environment
    """
    output_file = os.environ.get("GITHUB_OUTPUT")
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")

    if not output_file and not summary_file:
        return False

    # Write to GITHUB_OUTPUT
    if output_file:
        try:
            with open(output_file, "a") as f:
                f.write(f"passed={str(evaluation.passed).lower()}\n")
                f.write(f"overall_score={evaluation.scores.overall}\n")
                f.write(f"safety_score={evaluation.scores.safety}\n")
                f.write(f"compliance_score={evaluation.scores.compliance}\n")
                f.write(f"info_leakage_score={evaluation.scores.information_leakage}\n")
                f.write(f"role_adherence_score={evaluation.scores.role_adherence}\n")
                f.write(f"vulnerability_count={len(evaluation.vulnerabilities)}\n")

                # Count by severity
                critical = sum(
                    1 for v in evaluation.vulnerabilities if v.severity == "critical"
                )
                high = sum(
                    1 for v in evaluation.vulnerabilities if v.severity == "high"
                )
                f.write(f"critical_count={critical}\n")
                f.write(f"high_count={high}\n")
        except OSError:
            pass  # Silently fail if can't write

    # Write to GITHUB_STEP_SUMMARY
    if summary_file:
        try:
            with open(summary_file, "a") as f:
                f.write(generate_github_summary(evaluation, target))
                f.write("\n")
        except OSError:
            pass  # Silently fail if can't write

    return True


def is_github_actions() -> bool:
    """Check if running in GitHub Actions environment.

    Returns:
        True if running in GitHub Actions
    """
    return os.environ.get("GITHUB_ACTIONS") == "true"
