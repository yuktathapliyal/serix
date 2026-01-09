"""
Serix v2 - Unified Credential Wizard

Interactive credential setup with validation loop.

Law 9 Compliant: Complex display logic centralized here (CLI layer).
Reuses existing provider_setup.py functions where possible.
"""

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from serix_v2.cli.prompts.provider_setup import _save_key, prompt_api_key_entry
from serix_v2.cli.theme import COLOR_DIM, COLOR_ERROR, COLOR_SUCCESS, COLOR_WARNING
from serix_v2.core.constants import PROVIDER_CONSOLE_URLS
from serix_v2.core.contracts import CredentialAnalysisResult, ProviderRequirement
from serix_v2.services.credential_preflight import (
    update_requirement_presence,
    validate_all_keys,
)
from serix_v2.services.key_validator import KeyValidationResult

console = Console()

# Maximum validation retries to prevent infinite loops
MAX_VALIDATION_RETRIES = 3


def render_missing_summary(analysis: CredentialAnalysisResult) -> None:
    """Render summary of MISSING keys (env var not present)."""
    missing = analysis.missing_requirements
    present = analysis.present_requirements

    if len(missing) == 1:
        title = "API Key Required"
        intro = f"  Your configuration requires: {missing[0].provider.capitalize()}"
    else:
        title = "API Keys Required"
        intro = f"  Your configuration requires {len(analysis.requirements)} provider{'s' if len(analysis.requirements) > 1 else ''}:"

    # Build content
    lines = [intro, ""]

    # Show present keys first (with checkmark)
    for req in present:
        roles_str = ", ".join(req.roles)
        if req.is_target:
            roles_str = (
                f"target: {roles_str}" if "target" not in req.roles else "target"
            )
        else:
            roles_str = f"serix: {roles_str}"
        lines.append(
            f"    [{COLOR_SUCCESS}]✓[/{COLOR_SUCCESS}] {req.env_var:<25} found         ({roles_str})"
        )

    # Show missing keys (with X)
    for req in missing:
        roles_str = ", ".join(req.roles)
        if req.is_target:
            roles_str = (
                f"target: {roles_str}" if "target" not in req.roles else "target"
            )
        else:
            roles_str = f"serix: {roles_str}"
        lines.append(
            f"    [{COLOR_ERROR}]✗[/{COLOR_ERROR}] {req.env_var:<25} not found     ({roles_str})"
        )

    lines.append("")
    if len(missing) == 1:
        lines.append("  How would you like to proceed?")
    else:
        lines.append(
            f"  {len(missing)} API key{'s' if len(missing) > 1 else ''} missing. How would you like to proceed?"
        )
    lines.append("")
    lines.append("    [1] Set up now (interactive)")
    lines.append("    [2] Exit and configure manually")

    content = "\n".join(lines)
    console.print()
    console.print(Panel(content, title=title, border_style=COLOR_DIM))


def render_invalid_summary(
    invalid_reqs: list[ProviderRequirement],
    validation_results: dict[str, KeyValidationResult],
) -> None:
    """Render summary of INVALID keys (validation failed) with error reasons."""
    if len(invalid_reqs) == 1:
        title = "API Key Invalid"
    else:
        title = "API Keys Invalid"

    lines = [
        f"  {len(invalid_reqs)} key{'s' if len(invalid_reqs) > 1 else ''} failed validation:",
        "",
    ]

    for req in invalid_reqs:
        result = validation_results.get(req.provider)
        error_msg = result.error_message if result else "Unknown error"
        lines.append(
            f"    [{COLOR_ERROR}]✗[/{COLOR_ERROR}] {req.env_var:<25} {error_msg}"
        )

    lines.append("")
    lines.append("  How would you like to proceed?")
    lines.append("")
    lines.append("    [1] Re-enter keys now")
    lines.append("    [2] Exit and configure manually")

    content = "\n".join(lines)
    console.print()
    console.print(Panel(content, title=title, border_style=COLOR_WARNING))


def render_manual_setup_full(
    requirements: list[ProviderRequirement],
    original_command: str,
) -> None:
    """Render complete manual setup with command echo."""
    lines = ["  Set the following API keys before re-running:", ""]

    for req in requirements:
        console_url = PROVIDER_CONSOLE_URLS.get(req.provider, "")
        env_var = req.env_var

        roles_str = ", ".join(req.roles)
        lines.append(f"  {env_var} ({roles_str})")
        lines.append("  " + "─" * 42)
        lines.append(f"    Get key: {console_url}")
        lines.append("")
        lines.append(f"    Option A: export {env_var}=your-key-here")
        lines.append(f"    Option B: Add to .env: {env_var}=your-key-here")
        lines.append("")

    # Add command echo
    lines.append("  Then re-run:")
    lines.append(f"    {original_command}")

    content = "\n".join(lines)
    console.print()
    console.print(Panel(content, title="Manual Setup", border_style=COLOR_DIM))


def render_ci_missing_summary(analysis: CredentialAnalysisResult) -> None:
    """Render missing keys summary for CI mode (no interactive prompt)."""
    missing = analysis.missing_requirements

    console.print()
    console.print(f"  [{COLOR_ERROR}]✗ Missing API Keys[/{COLOR_ERROR}]")
    console.print()

    for req in missing:
        roles_str = ", ".join(req.roles)
        console.print(
            f"    [{COLOR_ERROR}]✗[/{COLOR_ERROR}] {req.env_var:<25} not found     ({roles_str})"
        )

    console.print()
    console.print("  Set the required environment variables and re-run.")
    console.print()


def render_ci_invalid_summary(
    invalid_reqs: list[ProviderRequirement],
    validation_results: dict[str, KeyValidationResult],
) -> None:
    """Render invalid keys summary for CI mode (no interactive prompt)."""
    console.print()
    console.print(f"  [{COLOR_ERROR}]✗ Invalid API Keys[/{COLOR_ERROR}]")
    console.print()

    for req in invalid_reqs:
        result = validation_results.get(req.provider)
        error_msg = result.error_message if result else "Unknown error"
        console.print(
            f"    [{COLOR_ERROR}]✗[/{COLOR_ERROR}] {req.env_var:<25} {error_msg}"
        )

    console.print()
    console.print("  Check your API keys and re-run.")
    console.print()


def render_max_retries_error() -> None:
    """Render error when max validation retries exceeded."""
    console.print()
    console.print(
        f"  [{COLOR_ERROR}]Maximum validation attempts exceeded.[/{COLOR_ERROR}]"
    )
    console.print("  Please check your API keys and try again.")
    console.print()


def render_all_valid() -> None:
    """Render success message when all keys are valid."""
    console.print()
    console.print(f"  [{COLOR_SUCCESS}]✓ All API keys validated.[/{COLOR_SUCCESS}]")
    console.print()


def prompt_choice() -> str:
    """Prompt user to choose between interactive and manual setup."""
    choice = Prompt.ask("Select [1-2]", default="1")
    return "interactive" if choice == "1" else "manual"


def prompt_sequential_keys(
    keys_to_enter: list[ProviderRequirement],
    context: str = "missing",
) -> dict[str, str]:
    """
    Prompt for each key with progress (1/N, 2/N).

    Args:
        keys_to_enter: List of provider requirements to prompt for.
        context: "missing" or "invalid" for contextual messaging.

    Returns:
        Dict of provider -> entered key value (empty string if cancelled).
    """
    results: dict[str, str] = {}
    total = len(keys_to_enter)

    for i, req in enumerate(keys_to_enter, 1):
        provider = req.provider
        console_url = PROVIDER_CONSOLE_URLS.get(provider, "")
        provider_title = provider.capitalize()

        # Build panel content
        roles_str = ", ".join(req.roles)
        panel_content = f"""
  Used for: {roles_str}
  Get a key at: {console_url}
"""

        title = f"{provider_title} API Key ({i}/{total})"
        console.print()
        console.print(Panel(panel_content, title=title, border_style=COLOR_DIM))

        # Use existing prompt function which handles validation
        key = prompt_api_key_entry(provider)

        if key:
            # Save key immediately
            saved = _save_key(provider, key)
            if saved:
                results[provider] = key
            else:
                results[provider] = ""
        else:
            # User cancelled
            results[provider] = ""
            break  # Don't continue to next key

    return results


def run_credential_wizard(
    analysis: CredentialAnalysisResult,
    original_command: str,
) -> bool:
    """
    Run the unified credential wizard with validation loop.

    Flow:
    1. Show missing keys → prompt to enter
    2. Validate ALL keys (including pre-existing)
    3. If any invalid → show invalid only → prompt to re-enter
    4. Loop until all valid or max retries

    Args:
        analysis: Result from analyze_requirements().
        original_command: The command the user typed (for "Then re-run" message).

    Returns:
        True if all keys valid, False if user chose manual or max retries exceeded.
    """
    # Phase 1: Handle MISSING keys
    if not analysis.all_present:
        render_missing_summary(analysis)
        choice = prompt_choice()

        if choice == "manual":
            render_manual_setup_full(analysis.missing_requirements, original_command)
            return False

        # Interactive: prompt for missing keys
        entered = prompt_sequential_keys(
            analysis.missing_requirements, context="missing"
        )

        # Check if user cancelled
        if not all(entered.values()):
            console.print(f"\n  [{COLOR_DIM}]Setup cancelled.[/{COLOR_DIM}]\n")
            return False

        # Update presence status
        update_requirement_presence(analysis.requirements)

    # Phase 2: VALIDATE all keys (including pre-existing)
    retries = 0
    while retries < MAX_VALIDATION_RETRIES:
        # Validate all present keys
        validation_results = validate_all_keys(analysis.requirements)

        # Find invalid keys
        invalid_reqs = [
            req
            for req in analysis.requirements
            if req.is_present
            and not validation_results.get(
                req.provider, KeyValidationResult(valid=False, provider=req.provider)
            ).valid
        ]

        if not invalid_reqs:
            # All valid!
            render_all_valid()
            return True

        # Show invalid summary
        render_invalid_summary(invalid_reqs, validation_results)
        choice = prompt_choice()

        if choice == "manual":
            render_manual_setup_full(invalid_reqs, original_command)
            return False

        # Re-enter invalid keys
        entered = prompt_sequential_keys(invalid_reqs, context="invalid")

        # Check if user cancelled
        if not all(entered.values()):
            console.print(f"\n  [{COLOR_DIM}]Setup cancelled.[/{COLOR_DIM}]\n")
            return False

        # Update presence status
        update_requirement_presence(analysis.requirements)
        retries += 1

    # Max retries exceeded
    render_max_retries_error()
    return False
