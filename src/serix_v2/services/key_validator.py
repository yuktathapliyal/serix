"""
Serix v2 - API Key Validator Service

Validates API keys for different LLM providers.

Law 2: CLI-is-a-Guest - This is a service, so NO typer/rich/click imports.
Returns Pydantic result objects for CLI to display.
"""

from pydantic import BaseModel

from serix_v2.core.constants import SUPPORTED_PROVIDERS


class KeyValidationResult(BaseModel):
    """Result of API key validation."""

    valid: bool
    provider: str
    error_message: str | None = None
    error_code: str | None = None  # e.g., "401", "timeout", "network"


def validate_openai_key(key: str, timeout: float = 5.0) -> KeyValidationResult:
    """
    Validate OpenAI API key by calling models.list().

    This endpoint is free (no tokens consumed) and confirms the key works.

    Args:
        key: OpenAI API key to validate
        timeout: Request timeout in seconds

    Returns:
        KeyValidationResult with validation status
    """
    try:
        import httpx

        response = httpx.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=timeout,
        )

        if response.status_code == 200:
            return KeyValidationResult(valid=True, provider="openai")
        elif response.status_code == 401:
            return KeyValidationResult(
                valid=False,
                provider="openai",
                error_message="Invalid API key (401 Unauthorized)",
                error_code="401",
            )
        else:
            return KeyValidationResult(
                valid=False,
                provider="openai",
                error_message=f"API error ({response.status_code})",
                error_code=str(response.status_code),
            )
    except httpx.TimeoutException:
        return KeyValidationResult(
            valid=False,
            provider="openai",
            error_message="Request timed out",
            error_code="timeout",
        )
    except httpx.RequestError as e:
        return KeyValidationResult(
            valid=False,
            provider="openai",
            error_message=f"Network error: {e}",
            error_code="network",
        )
    except ImportError:
        return KeyValidationResult(
            valid=False,
            provider="openai",
            error_message="httpx not installed",
            error_code="missing_dep",
        )


def validate_anthropic_key(key: str, timeout: float = 5.0) -> KeyValidationResult:
    """
    Validate Anthropic API key with a minimal completion.

    Uses max_tokens=1 to minimize cost while confirming the key works.

    Args:
        key: Anthropic API key to validate
        timeout: Request timeout in seconds

    Returns:
        KeyValidationResult with validation status
    """
    try:
        import httpx

        response = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-3-haiku-20240307",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "Hi"}],
            },
            timeout=timeout,
        )

        if response.status_code == 200:
            return KeyValidationResult(valid=True, provider="anthropic")
        elif response.status_code == 401:
            return KeyValidationResult(
                valid=False,
                provider="anthropic",
                error_message="Invalid API key (401 Unauthorized)",
                error_code="401",
            )
        else:
            return KeyValidationResult(
                valid=False,
                provider="anthropic",
                error_message=f"API error ({response.status_code})",
                error_code=str(response.status_code),
            )
    except httpx.TimeoutException:
        return KeyValidationResult(
            valid=False,
            provider="anthropic",
            error_message="Request timed out",
            error_code="timeout",
        )
    except httpx.RequestError as e:
        return KeyValidationResult(
            valid=False,
            provider="anthropic",
            error_message=f"Network error: {e}",
            error_code="network",
        )
    except ImportError:
        return KeyValidationResult(
            valid=False,
            provider="anthropic",
            error_message="httpx not installed",
            error_code="missing_dep",
        )


def validate_google_key(key: str, timeout: float = 5.0) -> KeyValidationResult:
    """
    Validate Google API key by calling list models endpoint.

    This endpoint is free (no tokens consumed) and confirms the key works.

    Args:
        key: Google API key to validate
        timeout: Request timeout in seconds

    Returns:
        KeyValidationResult with validation status
    """
    try:
        import httpx

        response = httpx.get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={key}",
            timeout=timeout,
        )

        if response.status_code == 200:
            return KeyValidationResult(valid=True, provider="google")
        elif response.status_code == 400 or response.status_code == 401:
            return KeyValidationResult(
                valid=False,
                provider="google",
                error_message="Invalid API key",
                error_code=str(response.status_code),
            )
        else:
            return KeyValidationResult(
                valid=False,
                provider="google",
                error_message=f"API error ({response.status_code})",
                error_code=str(response.status_code),
            )
    except httpx.TimeoutException:
        return KeyValidationResult(
            valid=False,
            provider="google",
            error_message="Request timed out",
            error_code="timeout",
        )
    except httpx.RequestError as e:
        return KeyValidationResult(
            valid=False,
            provider="google",
            error_message=f"Network error: {e}",
            error_code="network",
        )
    except ImportError:
        return KeyValidationResult(
            valid=False,
            provider="google",
            error_message="httpx not installed",
            error_code="missing_dep",
        )


def validate_key(provider: str, key: str, timeout: float = 5.0) -> KeyValidationResult:
    """
    Validate an API key for the specified provider.

    Args:
        provider: Provider name ("openai", "anthropic", "google")
        key: API key to validate
        timeout: Request timeout in seconds

    Returns:
        KeyValidationResult with validation status

    Raises:
        ValueError: If provider is not supported
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unknown provider '{provider}'. "
            f"Supported: {', '.join(SUPPORTED_PROVIDERS)}"
        )

    if provider == "openai":
        return validate_openai_key(key, timeout)
    elif provider == "anthropic":
        return validate_anthropic_key(key, timeout)
    elif provider == "google":
        return validate_google_key(key, timeout)
    else:
        # Should never reach here due to above check
        raise ValueError(f"Unknown provider: {provider}")
