"""
Serix v2 - CLI Prompts

Interactive prompts for user input.

Law 2 Compliance: This is in cli/, so typer/rich allowed.
"""

from serix_v2.cli.prompts.credential_wizard import (
    render_ci_invalid_summary,
    render_ci_missing_summary,
    render_manual_setup_full,
    run_credential_wizard,
)
from serix_v2.cli.prompts.provider_setup import (
    handle_missing_key,
    prompt_api_key_entry,
    prompt_provider_selection,
    run_full_onboarding,
)

__all__ = [
    # credential_wizard (Phase 19)
    "render_ci_invalid_summary",
    "render_ci_missing_summary",
    "render_manual_setup_full",
    "run_credential_wizard",
    # provider_setup (existing)
    "handle_missing_key",
    "prompt_api_key_entry",
    "prompt_provider_selection",
    "run_full_onboarding",
]
