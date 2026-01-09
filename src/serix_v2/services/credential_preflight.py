"""
Serix v2 - Credential Preflight Service

Analyzes all required providers upfront and checks key presence/validity.

Law 2 Compliant: No typer/rich imports. Returns Pydantic models.
"""

import os
from typing import Callable

from serix_v2.core.constants import (
    PROVIDER_ENV_VARS,
    SUPPORTED_PROVIDERS,
    infer_provider_from_model,
)
from serix_v2.core.contracts import CredentialAnalysisResult, ProviderRequirement
from serix_v2.core.errors import TargetCredentialError
from serix_v2.services.key_validator import KeyValidationResult, validate_key


def collect_serix_providers(
    base_provider: str | None,
    model_overrides: dict[str, str | None],
) -> dict[str, list[str]]:
    """
    Determine all providers needed from Serix model configuration.

    Args:
        base_provider: The base provider ("openai", "anthropic", "google") or None.
        model_overrides: Dict mapping role -> model name (may include None values).
            Example: {"attacker": "gpt-4o-mini", "judge": "claude-sonnet-4-20250514"}

    Returns:
        Dict mapping provider -> list of roles using it.
        Example: {"openai": ["attacker", "critic"], "anthropic": ["judge"]}
    """
    provider_roles: dict[str, list[str]] = {}

    # Process each model override
    for role, model in model_overrides.items():
        if model is None:
            # No override for this role - use base provider
            if base_provider:
                provider_roles.setdefault(base_provider, []).append(role)
        else:
            # Override specified - infer provider from model name
            inferred = infer_provider_from_model(model)
            if inferred:
                provider_roles.setdefault(inferred, []).append(role)
            elif base_provider:
                # Unknown model - fall back to base provider
                provider_roles.setdefault(base_provider, []).append(role)

    # If no model overrides and base provider set, use base for all roles
    if not model_overrides and base_provider:
        provider_roles[base_provider] = [
            "attacker",
            "critic",
            "analyzer",
            "judge",
            "patcher",
        ]

    return provider_roles


def analyze_requirements(
    serix_provider: str | None,
    model_overrides: dict[str, str | None],
    target_provider: str | None,
) -> CredentialAnalysisResult:
    """
    Analyze ALL required providers and check EXISTENCE of keys.

    Does NOT validate keys yet - just checks env vars exist.

    Args:
        serix_provider: The Serix provider (from --provider or auto-detected).
        model_overrides: Dict mapping role -> model name for individual overrides.
        target_provider: The target's provider (from config or dry preflight).

    Returns:
        CredentialAnalysisResult with all requirements and presence status.
    """
    requirements: list[ProviderRequirement] = []
    seen_providers: set[str] = set()

    # Collect Serix provider requirements
    serix_providers = collect_serix_providers(serix_provider, model_overrides)

    for provider, roles in serix_providers.items():
        if provider not in seen_providers and provider in SUPPORTED_PROVIDERS:
            env_var = PROVIDER_ENV_VARS.get(provider, f"{provider.upper()}_API_KEY")
            is_present = bool(os.environ.get(env_var))

            requirements.append(
                ProviderRequirement(
                    provider=provider,
                    env_var=env_var,
                    roles=roles,
                    is_target=False,
                    is_present=is_present,
                )
            )
            seen_providers.add(provider)

    # Add target provider requirement if specified and different
    if target_provider and target_provider in SUPPORTED_PROVIDERS:
        if target_provider not in seen_providers:
            env_var = PROVIDER_ENV_VARS.get(
                target_provider, f"{target_provider.upper()}_API_KEY"
            )
            is_present = bool(os.environ.get(env_var))

            requirements.append(
                ProviderRequirement(
                    provider=target_provider,
                    env_var=env_var,
                    roles=["target"],
                    is_target=True,
                    is_present=is_present,
                )
            )
        else:
            # Target uses same provider as Serix - update roles
            for req in requirements:
                if req.provider == target_provider:
                    req.roles = req.roles + ["target"]
                    break

    # Calculate summary
    missing_count = sum(1 for r in requirements if not r.is_present)
    all_present = missing_count == 0

    return CredentialAnalysisResult(
        requirements=requirements,
        missing_count=missing_count,
        all_present=all_present,
        target_provider=target_provider,
        target_provider_source="config" if target_provider else None,
    )


def validate_all_keys(
    requirements: list[ProviderRequirement],
    timeout: float = 5.0,
) -> dict[str, KeyValidationResult]:
    """
    Validate ALL keys by calling provider APIs.

    Args:
        requirements: List of provider requirements (with is_present=True).
        timeout: Timeout for each validation call.

    Returns:
        Dict mapping provider -> KeyValidationResult.
        Used after presence check to verify keys actually work.
    """
    results: dict[str, KeyValidationResult] = {}

    for req in requirements:
        if not req.is_present:
            # Key not present - can't validate
            results[req.provider] = KeyValidationResult(
                valid=False,
                provider=req.provider,
                error_message="API key not found in environment",
                error_code="missing",
            )
            continue

        # Get the key from environment
        key = os.environ.get(req.env_var, "")

        # Validate the key
        result = validate_key(req.provider, key, timeout=timeout)
        results[req.provider] = result

    return results


def run_dry_preflight(
    target_callable: Callable[[str], str],
    target_id: str,
    locator: str,
) -> tuple[str | None, str | None]:
    """
    Execute target once to detect its provider.

    Calls the target with a simple "hello" prompt to see if it works
    or throws a credential error that reveals the provider.

    Args:
        target_callable: The target function to call.
        target_id: Target ID for error context.
        locator: Target locator string for error context.

    Returns:
        Tuple of (detected_provider, error_message):
        - Success: (None, None) - target works, no additional provider needed
        - Credential error: (provider, error_msg) - detected provider from error
        - Other error: (None, error_msg) - couldn't detect provider
    """
    try:
        # Call target with simple prompt
        target_callable("hello")
        # Target succeeded - no additional provider credential needed
        return (None, None)
    except TargetCredentialError as e:
        # Target threw credential error - extract provider
        return (e.detected_provider, e.original_error)
    except Exception as e:
        # Other error - check if it looks like a credential error
        error_str = str(e).lower()

        # Try to detect provider from error message
        if "openai" in error_str or "api key" in error_str:
            if "openai" in error_str:
                return ("openai", str(e))
        if "anthropic" in error_str or "claude" in error_str:
            return ("anthropic", str(e))
        if "google" in error_str or "gemini" in error_str:
            return ("google", str(e))

        # Check for common API key error patterns
        if any(
            pattern in error_str
            for pattern in [
                "api_key",
                "apikey",
                "api-key",
                "authentication",
                "401",
                "unauthorized",
                "invalid key",
            ]
        ):
            # Looks like a credential error but can't determine provider
            return (None, str(e))

        # Not a credential error - target failed for other reasons
        return (None, str(e))


def update_requirement_presence(
    requirements: list[ProviderRequirement],
) -> list[ProviderRequirement]:
    """
    Re-check presence of keys after user has entered them.

    Args:
        requirements: List of provider requirements to check.

    Returns:
        Updated list with is_present refreshed from environment.
    """
    for req in requirements:
        req.is_present = bool(os.environ.get(req.env_var))
    return requirements
