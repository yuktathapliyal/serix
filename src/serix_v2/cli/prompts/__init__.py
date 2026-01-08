"""
Serix v2 - CLI Prompts

Interactive prompts for user input.

Law 2 Compliance: This is in cli/, so typer/rich allowed.
"""

from serix_v2.cli.prompts.provider_setup import (
    handle_missing_key,
    prompt_api_key_entry,
    prompt_provider_selection,
    run_full_onboarding,
)

__all__ = [
    "handle_missing_key",
    "prompt_api_key_entry",
    "prompt_provider_selection",
    "run_full_onboarding",
]
