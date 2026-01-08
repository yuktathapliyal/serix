"""
Tests for LiteLLM retry logic.

Tests the tenacity retry decorator on LiteLLMProvider.complete().
"""

from unittest.mock import MagicMock, patch

import litellm
import pytest

from serix_v2.providers import LiteLLMProvider


class TestRetryOnTransientErrors:
    """Test that transient errors trigger retry logic."""

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_retry_on_rate_limit_error(self, mock_litellm: MagicMock) -> None:
        """RateLimitError should trigger retry and succeed on second attempt."""
        # First call fails with RateLimitError, second succeeds
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Success after retry"

        # Set up the exception class
        mock_litellm.RateLimitError = litellm.RateLimitError
        mock_litellm.Timeout = litellm.Timeout
        mock_litellm.APIConnectionError = litellm.APIConnectionError

        mock_litellm.completion.side_effect = [
            litellm.RateLimitError(
                message="Rate limit exceeded",
                llm_provider="openai",
                model="gpt-4o",
            ),
            mock_response,
        ]

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        result = provider.complete(messages, model="gpt-4o")

        assert result == "Success after retry"
        assert mock_litellm.completion.call_count == 2

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_retry_on_timeout_error(self, mock_litellm: MagicMock) -> None:
        """Timeout should trigger retry and succeed on second attempt."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Success after timeout retry"

        mock_litellm.RateLimitError = litellm.RateLimitError
        mock_litellm.Timeout = litellm.Timeout
        mock_litellm.APIConnectionError = litellm.APIConnectionError

        mock_litellm.completion.side_effect = [
            litellm.Timeout(
                message="Request timed out",
                llm_provider="openai",
                model="gpt-4o",
            ),
            mock_response,
        ]

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        result = provider.complete(messages, model="gpt-4o")

        assert result == "Success after timeout retry"
        assert mock_litellm.completion.call_count == 2

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_retry_on_connection_error(self, mock_litellm: MagicMock) -> None:
        """APIConnectionError should trigger retry and succeed on second attempt."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Success after connection retry"

        mock_litellm.RateLimitError = litellm.RateLimitError
        mock_litellm.Timeout = litellm.Timeout
        mock_litellm.APIConnectionError = litellm.APIConnectionError

        mock_litellm.completion.side_effect = [
            litellm.APIConnectionError(
                message="Connection failed",
                llm_provider="openai",
                model="gpt-4o",
            ),
            mock_response,
        ]

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        result = provider.complete(messages, model="gpt-4o")

        assert result == "Success after connection retry"
        assert mock_litellm.completion.call_count == 2


class TestNoRetryOnPermanentErrors:
    """Test that permanent errors fail immediately without retry."""

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_no_retry_on_authentication_error(self, mock_litellm: MagicMock) -> None:
        """AuthenticationError should fail immediately without retry."""
        mock_litellm.RateLimitError = litellm.RateLimitError
        mock_litellm.Timeout = litellm.Timeout
        mock_litellm.APIConnectionError = litellm.APIConnectionError

        mock_litellm.completion.side_effect = litellm.AuthenticationError(
            message="Invalid API key",
            llm_provider="openai",
            model="gpt-4o",
        )

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        with pytest.raises(litellm.AuthenticationError):
            provider.complete(messages, model="gpt-4o")

        # Should only be called once (no retry)
        assert mock_litellm.completion.call_count == 1

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_no_retry_on_bad_request_error(self, mock_litellm: MagicMock) -> None:
        """BadRequestError should fail immediately without retry."""
        mock_litellm.RateLimitError = litellm.RateLimitError
        mock_litellm.Timeout = litellm.Timeout
        mock_litellm.APIConnectionError = litellm.APIConnectionError

        mock_litellm.completion.side_effect = litellm.BadRequestError(
            message="Invalid request",
            model="gpt-4o",
            llm_provider="openai",
        )

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        with pytest.raises(litellm.BadRequestError):
            provider.complete(messages, model="gpt-4o")

        # Should only be called once (no retry)
        assert mock_litellm.completion.call_count == 1


class TestMaxRetriesExhausted:
    """Test behavior when max retries are exhausted."""

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_raises_after_max_attempts(self, mock_litellm: MagicMock) -> None:
        """After 3 failed attempts, the original exception should be raised."""
        mock_litellm.RateLimitError = litellm.RateLimitError
        mock_litellm.Timeout = litellm.Timeout
        mock_litellm.APIConnectionError = litellm.APIConnectionError

        # All 3 attempts fail
        mock_litellm.completion.side_effect = litellm.RateLimitError(
            message="Rate limit exceeded",
            llm_provider="openai",
            model="gpt-4o",
        )

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        with pytest.raises(litellm.RateLimitError):
            provider.complete(messages, model="gpt-4o")

        # Should have tried 3 times
        assert mock_litellm.completion.call_count == 3

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_succeeds_on_third_attempt(self, mock_litellm: MagicMock) -> None:
        """Test success on the final (third) retry attempt."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Finally succeeded!"

        mock_litellm.RateLimitError = litellm.RateLimitError
        mock_litellm.Timeout = litellm.Timeout
        mock_litellm.APIConnectionError = litellm.APIConnectionError

        # First two fail, third succeeds
        mock_litellm.completion.side_effect = [
            litellm.RateLimitError(
                message="Rate limit exceeded",
                llm_provider="openai",
                model="gpt-4o",
            ),
            litellm.Timeout(
                message="Request timed out",
                llm_provider="openai",
                model="gpt-4o",
            ),
            mock_response,
        ]

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        result = provider.complete(messages, model="gpt-4o")

        assert result == "Finally succeeded!"
        assert mock_litellm.completion.call_count == 3
