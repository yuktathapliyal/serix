"""
Tests for TargetCredentialError.

These tests verify:
1. Provider detection from error messages
2. Error class inheritance
3. Field population
"""

from serix_v2.core.errors import (
    SerixError,
    TargetCredentialError,
    TargetUnreachableError,
)

# =============================================================================
# Provider Detection Tests
# =============================================================================


def test_credential_error_detects_openai() -> None:
    """OpenAI API key errors should detect 'openai' provider."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="The api_key client option must be set by setting OPENAI_API_KEY",
    )
    assert error.detected_provider == "openai"


def test_credential_error_detects_openai_from_gpt() -> None:
    """GPT model errors should detect 'openai' provider."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="gpt-4 requires authentication",
    )
    assert error.detected_provider == "openai"


def test_credential_error_detects_anthropic() -> None:
    """Anthropic API key errors should detect 'anthropic' provider."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="Anthropic API key not found",
    )
    assert error.detected_provider == "anthropic"


def test_credential_error_detects_anthropic_from_claude() -> None:
    """Claude model errors should detect 'anthropic' provider."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="claude-3 authentication failed",
    )
    assert error.detected_provider == "anthropic"


def test_credential_error_detects_google() -> None:
    """Google API key errors should detect 'google' provider."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="Google API key invalid",
    )
    assert error.detected_provider == "google"


def test_credential_error_detects_google_from_gemini() -> None:
    """Gemini model errors should detect 'google' provider."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="gemini-pro requires API key",
    )
    assert error.detected_provider == "google"


def test_credential_error_none_when_unknown() -> None:
    """Unknown providers should return None."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="Some generic auth error",
    )
    assert error.detected_provider is None


def test_credential_error_case_insensitive_detection() -> None:
    """Provider detection should be case insensitive."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="OPENAI_API_KEY environment variable not set",
    )
    assert error.detected_provider == "openai"


# =============================================================================
# Error Class Tests
# =============================================================================


def test_credential_error_is_serix_error() -> None:
    """TargetCredentialError should be a SerixError subclass."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="API key error",
    )
    assert isinstance(error, SerixError)


def test_credential_error_not_unreachable_error() -> None:
    """TargetCredentialError should NOT be a TargetUnreachableError."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="API key error",
    )
    assert not isinstance(error, TargetUnreachableError)


def test_credential_error_has_all_fields() -> None:
    """TargetCredentialError should have all required fields."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:func",
        original_error="Missing key",
    )
    assert error.target_id == "t_test"
    assert error.locator == "test.py:func"
    assert error.original_error == "Missing key"
    assert hasattr(error, "detected_provider")


def test_credential_error_str_contains_context() -> None:
    """TargetCredentialError string should contain useful context."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:func",
        original_error="OPENAI_API_KEY not set",
    )
    error_str = str(error)
    assert "t_test" in error_str
    assert "OPENAI_API_KEY not set" in error_str


def test_credential_error_preserves_original_error() -> None:
    """Original error message should be preserved exactly."""
    original = "The api_key client option must be set either by passing api_key to the client or by setting the OPENAI_API_KEY environment variable"
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:func",
        original_error=original,
    )
    assert error.original_error == original


# =============================================================================
# Edge Cases
# =============================================================================


def test_credential_error_empty_original() -> None:
    """Empty original_error should not crash."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="",
    )
    assert error.detected_provider is None
    assert error.original_error == ""


def test_credential_error_multiple_providers_in_message() -> None:
    """When multiple provider names appear, first match wins (openai)."""
    # OpenAI is checked first in the detection logic
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="Error with openai anthropic google",
    )
    assert error.detected_provider == "openai"


def test_credential_error_authentication_keyword() -> None:
    """'authentication' keyword should not affect provider detection."""
    error = TargetCredentialError(
        target_id="t_test",
        locator="test.py:test",
        original_error="authentication failed for the service",
    )
    # No provider keywords, just 'authentication'
    assert error.detected_provider is None
