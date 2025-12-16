"""Reporting module - Rich console output, HTML reports, JSON export, and live UI."""

from serix.report.console import (
    print_attack_results,
    print_banner,
    print_fuzz_result,
    print_fuzz_summary,
    print_recording_summary,
)
from serix.report.github import (
    generate_github_summary,
    generate_pr_comment,
    is_github_actions,
    write_github_output,
)
from serix.report.html import (
    EvaluationReportData,
    generate_evaluation_report,
    generate_html_report,
)
from serix.report.json_export import SerixReport, export_json, to_dict
from serix.report.live_ui import AttackState, LiveAttackUI

__all__ = [
    # Console output
    "print_banner",
    "print_recording_summary",
    "print_fuzz_result",
    "print_fuzz_summary",
    "print_attack_results",
    # HTML reports
    "generate_html_report",
    "generate_evaluation_report",
    "EvaluationReportData",
    # JSON export
    "export_json",
    "to_dict",
    "SerixReport",
    # GitHub Actions
    "generate_pr_comment",
    "generate_github_summary",
    "write_github_output",
    "is_github_actions",
    # Live UI
    "LiveAttackUI",
    "AttackState",
]
