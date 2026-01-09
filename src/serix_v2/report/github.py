"""GitHub Actions Output Formatter for Serix v2.

Phase 10B: Transforms JSONReportSchema into GitHub Actions annotations and job summary.

Output Types:
    1. ::error:: annotations - For successful exploits (appear in PR diff)
    2. ::warning:: annotations - For regressions (defended → exploited)
    3. GITHUB_STEP_SUMMARY - Markdown job summary

Law 1: No raw dicts - uses Pydantic models (GitHubOutput, JSONReportSchema)
Law 2: No typer/rich/click imports
Law 4: No module-level globals - all state in class instances
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from pydantic import BaseModel

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from serix_v2.report.schema import (
        JSONReportSchema,
        RegressionTransitionInfo,
        VulnerabilityInfo,
    )


# ============================================================================
# OUTPUT MODEL
# ============================================================================


class GitHubOutput(BaseModel):
    """Structured GitHub Actions output.

    Law 1: Pydantic model for typed contract.

    Attributes:
        annotations: String for stdout (::error:: and ::warning:: lines)
        summary: Markdown string for GITHUB_STEP_SUMMARY
    """

    annotations: str
    summary: str


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def extract_file_path(locator: str) -> str | None:
    """Extract file path from target locator.

    Args:
        locator: Target locator string, e.g., "src/agent.py:respond"
                 or "http://localhost:8000"

    Returns:
        File path portion (e.g., "src/agent.py") or None for HTTP URLs

    Examples:
        >>> extract_file_path("src/agent.py:respond")
        'src/agent.py'
        >>> extract_file_path("http://localhost:8000")
        None
        >>> extract_file_path("examples/victim.py:golden_victim")
        'examples/victim.py'
    """
    if locator.startswith(("http://", "https://")):
        return None
    return locator.split(":")[0]


def get_score_emoji(score: int) -> str:
    """Map score (0-100) to GitHub emoji.

    Args:
        score: Security score 0-100

    Returns:
        GitHub markdown emoji string
    """
    if score >= 80:
        return ":white_check_mark:"
    if score >= 60:
        return ":yellow_circle:"
    if score >= 40:
        return ":orange_circle:"
    return ":red_circle:"


def get_severity_emoji(severity: str) -> str:
    """Map severity level to GitHub emoji.

    Args:
        severity: 'critical', 'high', 'medium', 'low'

    Returns:
        GitHub markdown emoji string
    """
    severity_lower = severity.lower() if severity else ""
    if severity_lower == "critical":
        return ":red_circle:"
    if severity_lower == "high":
        return ":orange_circle:"
    if severity_lower == "medium":
        return ":yellow_circle:"
    if severity_lower == "low":
        return ":large_blue_circle:"
    return ":white_circle:"


def escape_github_message(text: str) -> str:
    """Escape text for GitHub Actions annotation messages.

    GitHub annotations use :: as delimiter, so we need to escape them.
    Also escapes newlines since annotations must be single-line.

    Args:
        text: Raw message text

    Returns:
        Escaped text safe for GitHub annotations
    """
    if not text:
        return ""
    # Replace :: with escaped version, newlines with spaces
    return text.replace("::", ": :").replace("\n", " ").replace("\r", "")


# ============================================================================
# FORMATTER CLASS
# ============================================================================


class GitHubOutputFormatter:
    """Transforms JSONReportSchema into GitHub Actions output.

    Law 4: Stateless - no instance state beyond configuration.

    Features:
        - ::error:: annotations for exploits (per vulnerability)
        - ::warning:: annotations for regressions
        - Markdown job summary with "What's Next?" section
    """

    def format(self, report: "JSONReportSchema") -> GitHubOutput:
        """Format report for GitHub Actions.

        Args:
            report: JSONReportSchema from Phase 9A

        Returns:
            GitHubOutput with annotations and summary strings
        """
        return GitHubOutput(
            annotations=self._format_annotations(report),
            summary=self._format_summary(report),
        )

    def _format_annotations(self, report: "JSONReportSchema") -> str:
        """Generate ::error:: and ::warning:: annotation lines.

        Args:
            report: JSONReportSchema

        Returns:
            Multi-line string with all annotations
        """
        lines: list[str] = []

        # Extract file path (may be None for HTTP targets)
        file_path = extract_file_path(report.target.locator)

        # Error annotations for each vulnerability (successful exploit)
        for vuln in report.vulnerabilities:
            lines.append(self._format_error_annotation(vuln, file_path))

        # Warning annotations for regressions
        for transition in report.regression.transitions:
            if transition.transition_type == "regression":
                lines.append(self._format_warning_annotation(transition))

        return "\n".join(lines)

    def _format_error_annotation(
        self,
        vuln: "VulnerabilityInfo",
        file_path: str | None,
    ) -> str:
        """Format single ::error:: annotation for an exploit.

        Args:
            vuln: Vulnerability info from successful exploit
            file_path: Target file path or None for HTTP targets

        Returns:
            Single ::error:: line
        """
        confidence_pct = int(vuln.confidence * 100)
        message = (
            f"Exploit succeeded: {vuln.scenario} achieved goal "
            f"'{vuln.goal}' ({confidence_pct}% confidence)"
        )
        message = escape_github_message(message)

        if file_path:
            return f"::error file={file_path}::{message}"
        return f"::error::{message}"

    def _format_warning_annotation(
        self,
        transition: "RegressionTransitionInfo",
    ) -> str:
        """Format single ::warning:: annotation for a regression.

        Args:
            transition: Regression transition info

        Returns:
            Single ::warning:: line
        """
        message = (
            f"Regression detected: {transition.strategy} attack on "
            f"'{transition.goal}' now succeeds (was defended)"
        )
        return f"::warning::{escape_github_message(message)}"

    def _format_summary(self, report: "JSONReportSchema") -> str:
        """Generate Markdown for GITHUB_STEP_SUMMARY.

        Args:
            report: JSONReportSchema

        Returns:
            Markdown string for job summary
        """
        lines: list[str] = []

        # Header
        lines.append("# Serix Security Scan")
        lines.append("")

        # Status
        if report.summary.passed:
            lines.append("## :white_check_mark: PASSED")
        else:
            lines.append("## :x: FAILED")
        lines.append("")

        # Target
        lines.append(f"**Target:** `{report.target.locator}`")
        if report.target.name:
            lines.append(f"**Alias:** `{report.target.name}`")
        lines.append("")

        # Score table
        lines.extend(
            [
                "| Metric | Value |",
                "|--------|-------|",
                f"| Score | **{report.summary.score}**/100 {get_score_emoji(report.summary.score)} |",
                f"| Grade | **{report.summary.grade}** |",
                f"| Exploited | {report.summary.exploited} |",
                f"| Defended | {report.summary.defended} |",
                f"| Duration | {report.summary.duration_seconds:.1f}s |",
                "",
            ]
        )

        # Vulnerabilities section
        if report.vulnerabilities:
            lines.append(f"### Vulnerabilities ({len(report.vulnerabilities)})")
            lines.append("")
            for vuln in report.vulnerabilities:
                emoji = get_severity_emoji(vuln.severity)
                confidence_pct = int(vuln.confidence * 100)
                lines.append(
                    f"- {emoji} **{vuln.scenario}**: {vuln.goal} "
                    f"({confidence_pct}% confidence)"
                )
            lines.append("")

        # Regressions section
        regression_count = sum(
            1
            for t in report.regression.transitions
            if t.transition_type == "regression"
        )
        if regression_count > 0:
            lines.append(f"### Regressions ({regression_count})")
            lines.append("")
            for t in report.regression.transitions:
                if t.transition_type == "regression":
                    lines.append(
                        f"- :warning: `{t.strategy}` attack on '{t.goal}' "
                        "now succeeds (was defended)"
                    )
            lines.append("")

        # What's Next section (only if exploits found)
        if report.vulnerabilities:
            lines.extend(
                [
                    "### What's Next?",
                    "",
                    "1. **Review the HTML Report** - Download the `serix-report.html` "
                    "artifact for an interactive dashboard with full attack transcripts",
                    "2. **Apply Healing Patches** - The HTML report includes AI-generated "
                    "patches to fix identified vulnerabilities",
                    "3. **Re-run Serix** - After applying fixes, run `serix test` again "
                    "to verify improvements",
                    "",
                ]
            )

        # Footer
        lines.append("---")
        lines.append("*Generated by [Serix](https://github.com/anthropics/serix)*")

        return "\n".join(lines)


# ============================================================================
# UTILITY FUNCTION
# ============================================================================


def write_github_output(output: GitHubOutput) -> bool:
    """Write output to GitHub Actions environment files.

    Automatically detects if running in GitHub Actions by checking
    for GITHUB_OUTPUT and GITHUB_STEP_SUMMARY environment variables.

    Args:
        output: GitHubOutput from GitHubOutputFormatter.format()

    Returns:
        True if any output was written, False if not in CI environment
    """
    output_file = os.environ.get("GITHUB_OUTPUT")
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")

    if not output_file and not summary_file:
        return False

    wrote = False

    # Write annotations to stdout (GitHub captures from stdout)
    if output.annotations:
        print(output.annotations)
        wrote = True

    # Write summary to GITHUB_STEP_SUMMARY
    if summary_file and output.summary:
        try:
            with open(summary_file, "a", encoding="utf-8") as f:
                f.write(output.summary)
                f.write("\n")
            wrote = True
        except OSError as e:
            logger.warning(
                f"Failed to write GitHub step summary to {summary_file}: {e}"
            )

    return wrote


def is_github_actions() -> bool:
    """Check if running in GitHub Actions environment.

    Returns:
        True if GITHUB_ACTIONS environment variable is 'true'
    """
    return os.environ.get("GITHUB_ACTIONS") == "true"
