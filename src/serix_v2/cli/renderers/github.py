"""
Serix v2 - GitHub Actions Renderer

Thin wrapper around serix_v2.report.GitHubOutputFormatter.

Law 2 Compliance: This is in cli/, so typer/rich/click allowed.
Actual formatting logic is in report.github (Law 1 compliant).
"""

from serix_v2.core.contracts import CampaignResult
from serix_v2.report import (
    GitHubOutputFormatter,
    is_github_actions,
    write_github_output,
)


def write_github_annotations(result: CampaignResult) -> None:
    """
    Write GitHub Actions annotations for exploits and regressions.

    Outputs ::error:: for exploits and ::warning:: for regressions.
    Only outputs when running in GitHub Actions environment.

    Args:
        result: Campaign result to format
    """
    if not is_github_actions():
        return

    formatter = GitHubOutputFormatter()
    output = formatter.format(result)

    # Output annotations to stdout
    for annotation in output.annotations:
        print(annotation)


def write_step_summary(result: CampaignResult) -> None:
    """
    Write GitHub Actions step summary with markdown report.

    Uses GITHUB_STEP_SUMMARY environment variable to display
    a formatted summary in the Actions UI.

    Args:
        result: Campaign result to format
    """
    if not is_github_actions():
        return

    formatter = GitHubOutputFormatter()
    output = formatter.format(result)

    # Write summary to GITHUB_STEP_SUMMARY
    write_github_output(output.summary)
