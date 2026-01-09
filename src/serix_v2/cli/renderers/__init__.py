"""
Serix v2 - CLI Renderers

Display formatting for CLI output.

Law 2 Compliance: All Rich formatting code lives here,
not in engine/ or services/.

Modules:
- console.py: Rich console output (tables, progress, panels)
- github.py: GitHub Actions annotations and step summary
"""

from serix_v2.cli.renderers.console import (
    handle_auth_error,
    render_api_error,
    render_auth_error,
    render_campaign_result,
    render_findings,
    render_grade_panel,
    render_init_exists,
    render_init_success,
    render_mixed_provider_warning,
    render_no_targets_found,
    render_status_table,
    render_target_not_found,
    render_target_unreachable,
)
from serix_v2.cli.renderers.github import write_github_annotations, write_step_summary

__all__ = [
    # Console renderers
    "handle_auth_error",
    "render_api_error",
    "render_auth_error",
    "render_campaign_result",
    "render_findings",
    "render_grade_panel",
    "render_init_exists",
    "render_init_success",
    "render_mixed_provider_warning",
    "render_no_targets_found",
    "render_status_table",
    "render_target_not_found",
    "render_target_unreachable",
    # GitHub renderers
    "write_github_annotations",
    "write_step_summary",
]
