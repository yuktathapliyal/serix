"""Reporting module - Rich console output and HTML reports."""

from serix.report.console import (
    print_attack_results,
    print_banner,
    print_fuzz_result,
    print_fuzz_summary,
    print_recording_summary,
)
from serix.report.html import generate_html_report

__all__ = [
    "print_banner",
    "print_recording_summary",
    "print_fuzz_result",
    "print_fuzz_summary",
    "print_attack_results",
    "generate_html_report",
]
