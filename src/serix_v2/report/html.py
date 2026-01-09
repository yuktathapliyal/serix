"""HTML Report Generator for Serix v2.

Phase 10A: Transforms JSONReportSchema into self-contained HTML dashboard.

Law 1: No raw dicts - uses JSONReportSchema (Pydantic model)
Law 2: No typer/rich/click imports
Law 4: No module-level globals - all state in class instances
"""

from __future__ import annotations

import html as html_lib
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, PackageLoader, select_autoescape

if TYPE_CHECKING:
    from serix_v2.report.schema import JSONReportSchema, VulnerabilityInfo


# ============================================================================
# HELPER FUNCTIONS (Jinja2 Filters)
# ============================================================================


def get_score_color(score: int | None) -> str:
    """Map score (0-100) to CSS class name.

    Args:
        score: Security score 0-100, or None if missing

    Returns:
        CSS class name: 'green', 'yellow', 'orange', 'red', or 'muted'

    Note:
        Returns 'muted' for None (missing data), not 'red' (failed).
        This prevents misleading users when data is unavailable.
    """
    if score is None:
        return "muted"
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    if score >= 40:
        return "orange"
    return "red"


def get_severity_color(severity: str) -> str:
    """Map severity level to CSS class name.

    Args:
        severity: 'critical', 'high', 'medium', 'low' (case-insensitive)

    Returns:
        CSS class name: 'critical', 'high', 'medium', 'low', or 'muted'
    """
    severity_lower = severity.lower() if severity else ""
    if severity_lower == "critical":
        return "critical"
    if severity_lower == "high":
        return "high"
    if severity_lower == "medium":
        return "medium"
    if severity_lower == "low":
        return "low"
    return "muted"


def get_grade_color(grade: str) -> str:
    """Map letter grade (A-F) to CSS class name.

    Args:
        grade: Letter grade 'A', 'B', 'C', 'D', 'F' (case-insensitive)

    Returns:
        CSS class name: 'green' for A-B, 'yellow' for C, 'orange' for D, 'red' for F
    """
    grade_upper = grade.upper() if grade else ""
    if grade_upper in ("A", "B"):
        return "green"
    if grade_upper == "C":
        return "yellow"
    if grade_upper == "D":
        return "orange"
    if grade_upper == "F":
        return "red"
    return "muted"


def format_duration(seconds: float | None) -> str:
    """Format duration to human-readable string.

    Args:
        seconds: Duration in seconds, or None

    Returns:
        Human-readable string like '45.3s', '2m 5s', '1h 2m 5s'

    Examples:
        >>> format_duration(45.3)
        '45.3s'
        >>> format_duration(125.0)
        '2m 5s'
        >>> format_duration(3725.0)
        '1h 2m 5s'
        >>> format_duration(None)
        '-'
    """
    if seconds is None:
        return "-"

    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    remaining_seconds = int(seconds % 60)

    if minutes < 60:
        if remaining_seconds > 0:
            return f"{minutes}m {remaining_seconds}s"
        return f"{minutes}m"

    hours = minutes // 60
    remaining_minutes = minutes % 60

    parts = [f"{hours}h"]
    if remaining_minutes > 0:
        parts.append(f"{remaining_minutes}m")
    if remaining_seconds > 0:
        parts.append(f"{remaining_seconds}s")

    return " ".join(parts)


def escape_html(text: str | None) -> str:
    """Escape HTML special characters for safe rendering.

    Args:
        text: Raw text that may contain HTML special characters

    Returns:
        HTML-escaped string safe for rendering

    Note:
        Uses Python's html.escape() for comprehensive escaping.
    """
    if text is None:
        return ""
    return html_lib.escape(str(text))


def format_diff(diff_text: str | None) -> str:
    """Wrap diff in <pre> with overflow handling and line coloring.

    Args:
        diff_text: Unified diff string, or None

    Returns:
        HTML wrapped in <pre class="diff-content"> with:
        - overflow-x: auto; (prevents layout stretch on long lines)
        - <span class="diff-add"> for + lines
        - <span class="diff-remove"> for - lines

    Note:
        The <pre> wrapper is CRITICAL - system prompts can have very
        long lines that would otherwise stretch the entire dashboard.
    """
    if not diff_text:
        return ""

    lines = diff_text.split("\n")
    formatted_lines = []

    for line in lines:
        escaped_line = html_lib.escape(line)
        if line.startswith("+") and not line.startswith("+++"):
            formatted_lines.append(f'<span class="diff-add">{escaped_line}</span>')
        elif line.startswith("-") and not line.startswith("---"):
            formatted_lines.append(f'<span class="diff-remove">{escaped_line}</span>')
        elif line.startswith("@@"):
            formatted_lines.append(f'<span class="diff-hunk">{escaped_line}</span>')
        else:
            formatted_lines.append(escaped_line)

    inner_html = "\n".join(formatted_lines)
    return f'<pre class="diff-content">{inner_html}</pre>'


def smart_truncate(
    text: str | None, length: int = 300, full_length: int = 1000
) -> dict[str, str | bool]:
    """Truncate long text with metadata for "View Full" toggle.

    Args:
        text: Original text to potentially truncate
        length: Truncation point (default 300 chars)
        full_length: Threshold to trigger truncation (default 1000 chars)

    Returns:
        Dictionary with:
        - 'text': str - Truncated or original text
        - 'is_truncated': bool - Whether truncation occurred
        - 'full_text': str - Original text for hidden element

    Note:
        Only truncates if len(text) > full_length, cutting at 'length' chars.
    """
    if text is None:
        return {"text": "", "is_truncated": False, "full_text": ""}

    if len(text) <= full_length:
        return {"text": text, "is_truncated": False, "full_text": text}

    truncated = text[:length] + "..."
    return {"text": truncated, "is_truncated": True, "full_text": text}


# ============================================================================
# GENERATOR CLASS
# ============================================================================


class HTMLReportGenerator:
    """Transforms JSONReportSchema into self-contained HTML string.

    Law 4: Stateless - all state is in the Jinja2 environment.

    Features:
        - Progressive enhancement (tabs with CSS fallback)
        - Smart truncation for large messages
        - Diff highlighting for healing patches
        - Print-friendly styles
    """

    def __init__(self) -> None:
        """Initialize Jinja2 environment with PackageLoader and custom filters."""
        self._env = Environment(
            loader=PackageLoader("serix_v2.report", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )

        # Register custom filters
        self._env.filters["score_color"] = get_score_color
        self._env.filters["severity_color"] = get_severity_color
        self._env.filters["grade_color"] = get_grade_color
        self._env.filters["format_duration"] = format_duration
        self._env.filters["escape_html"] = escape_html
        self._env.filters["format_diff"] = format_diff
        self._env.filters["smart_truncate"] = smart_truncate

    def render(self, report: "JSONReportSchema") -> str:
        """Render report to HTML string.

        Args:
            report: JSONReportSchema from Phase 9A

        Returns:
            Complete HTML string ready for file writing

        Note:
            Pure transformation - no I/O operations.
        """
        template = self._env.get_template("report.html.j2")

        # Extract top exploits for dashboard
        top_exploits = self._get_top_exploits(report, n=5)

        return template.render(
            report=report,
            top_exploits=top_exploits,
        )

    def _get_top_exploits(
        self, report: "JSONReportSchema", n: int = 5
    ) -> list[tuple[int, "VulnerabilityInfo"]]:
        """Extract top N most critical exploits for Executive Dashboard.

        Sorted by: severity (critical > high > medium > low), then confidence.

        Args:
            report: The JSON report schema
            n: Number of top exploits to return (default 5)

        Returns:
            List of tuples: (loop_index, vulnerability) for deep linking
        """
        # Define severity order (lower = more critical)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        # Create indexed list for sorting while preserving original position
        indexed_vulns: list[tuple[int, VulnerabilityInfo]] = [
            (i + 1, v) for i, v in enumerate(report.vulnerabilities)
        ]

        # Sort by severity (critical first), then by confidence (higher first)
        indexed_vulns.sort(
            key=lambda x: (
                severity_order.get(x[1].severity.lower(), 4),
                -(x[1].confidence or 0),
            )
        )

        return indexed_vulns[:n]


# ============================================================================
# CONVENIENCE UTILITY
# ============================================================================


def write_html_report(report: "JSONReportSchema", output_path: Path) -> Path:
    """Generate and write HTML report to file.

    Args:
        report: JSONReportSchema to render
        output_path: Where to write the HTML file

    Returns:
        Path to the written file

    Note:
        Creates parent directories if they don't exist.
    """
    generator = HTMLReportGenerator()
    html_content = generator.render(report)

    # Ensure parent directories exist
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write with UTF-8 encoding
    output_path.write_text(html_content, encoding="utf-8")

    return output_path
