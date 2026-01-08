"""
Tests for LiteLLMProvider.

Uses mocking to test the provider without making real API calls.
"""

from unittest.mock import MagicMock, patch

import pytest

from serix_v2.core.protocols import LLMProvider
from serix_v2.providers import LiteLLMProvider
from serix_v2.providers.llm.litellm_provider import normalize_model


class TestProtocolCompliance:
    """Test that LiteLLMProvider satisfies the LLMProvider protocol."""

    def test_satisfies_protocol(self) -> None:
        """Verify LiteLLMProvider is @runtime_checkable compatible."""
        provider = LiteLLMProvider()
        assert isinstance(provider, LLMProvider)

    def test_has_complete_method(self) -> None:
        """Verify complete method exists with correct signature."""
        provider = LiteLLMProvider()
        assert hasattr(provider, "complete")
        assert callable(provider.complete)


class TestCompleteMethod:
    """Test the complete method."""

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_complete_calls_litellm(self, mock_litellm: MagicMock) -> None:
        """Test that complete() calls litellm.completion correctly."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Hello from LLM!"
        mock_litellm.completion.return_value = mock_response

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Hello"}]
        result = provider.complete(messages, model="gpt-4o")

        # Verify result
        assert result == "Hello from LLM!"

        # Verify litellm.completion was called correctly
        mock_litellm.completion.assert_called_once_with(
            model="gpt-4o",
            messages=messages,
            temperature=0.7,  # Default
        )

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_complete_with_custom_temperature(self, mock_litellm: MagicMock) -> None:
        """Test complete() with custom temperature."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_litellm.completion.return_value = mock_response

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]
        provider.complete(messages, model="gpt-4o", temperature=0.2)

        mock_litellm.completion.assert_called_once_with(
            model="gpt-4o",
            messages=messages,
            temperature=0.2,
        )

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_complete_handles_none_content(self, mock_litellm: MagicMock) -> None:
        """Test that None content returns empty string."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = None
        mock_litellm.completion.return_value = mock_response

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]
        result = provider.complete(messages, model="gpt-4o")

        assert result == ""

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_complete_with_system_message(self, mock_litellm: MagicMock) -> None:
        """Test complete() with system message."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_litellm.completion.return_value = mock_response

        provider = LiteLLMProvider()
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello"},
        ]
        provider.complete(messages, model="gpt-4o")

        mock_litellm.completion.assert_called_once()
        call_args = mock_litellm.completion.call_args
        assert call_args.kwargs["messages"] == messages


class TestCompleteWithMetadata:
    """Test the extended complete_with_metadata method."""

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_returns_metadata(self, mock_litellm: MagicMock) -> None:
        """Test that complete_with_metadata returns full metadata."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.model = "gpt-4o-2024-05-13"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 5
        mock_response.usage.total_tokens = 15
        mock_litellm.completion.return_value = mock_response

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]
        result = provider.complete_with_metadata(messages, model="gpt-4o")

        assert result["content"] == "Response"
        assert result["model"] == "gpt-4o-2024-05-13"
        assert result["usage"]["prompt_tokens"] == 10
        assert result["usage"]["completion_tokens"] == 5
        assert result["usage"]["total_tokens"] == 15
        assert result["raw_response"] == mock_response


class TestInitialization:
    """Test provider initialization."""

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    @patch.dict("os.environ", {}, clear=True)
    def test_api_key_sets_env_var(self, mock_litellm: MagicMock) -> None:
        """Test that api_key sets OPENAI_API_KEY env var."""
        import os

        LiteLLMProvider(api_key="test-key")
        assert os.environ.get("OPENAI_API_KEY") == "test-key"

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_drop_params_default(self, mock_litellm: MagicMock) -> None:
        """Test that drop_params is True by default."""
        LiteLLMProvider()
        assert mock_litellm.drop_params is True

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_suppress_debug_default(self, mock_litellm: MagicMock) -> None:
        """Test that debug info is suppressed by default."""
        LiteLLMProvider()
        assert mock_litellm.suppress_debug_info is True


class TestRepr:
    """Test string representation."""

    def test_repr(self) -> None:
        """Test repr returns useful string."""
        provider = LiteLLMProvider()
        assert repr(provider) == "LiteLLMProvider()"


class TestNormalizeModel:
    """Test model name normalization for litellm routing."""

    # OpenAI models - should NOT be prefixed (litellm auto-detects)
    @pytest.mark.parametrize(
        "model",
        [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-3.5-turbo",
            "o1",
            "o1-preview",
            "o1-mini",
        ],
    )
    def test_openai_models_unchanged(self, model: str) -> None:
        """OpenAI models should not be prefixed."""
        assert normalize_model(model) == model

    # Anthropic models - should be prefixed with anthropic/
    @pytest.mark.parametrize(
        "model,expected",
        [
            # New Claude 4 naming
            ("claude-haiku-4-20250514", "anthropic/claude-haiku-4-20250514"),
            ("claude-sonnet-4-20250514", "anthropic/claude-sonnet-4-20250514"),
            ("claude-opus-4-20250514", "anthropic/claude-opus-4-20250514"),
            # Old Claude 3 naming
            ("claude-3-opus-20240229", "anthropic/claude-3-opus-20240229"),
            ("claude-3-sonnet-20240229", "anthropic/claude-3-sonnet-20240229"),
            ("claude-3-haiku-20240307", "anthropic/claude-3-haiku-20240307"),
        ],
    )
    def test_anthropic_models_prefixed(self, model: str, expected: str) -> None:
        """Anthropic models should be prefixed with anthropic/."""
        assert normalize_model(model) == expected

    # Google models - should be prefixed with gemini/
    @pytest.mark.parametrize(
        "model,expected",
        [
            ("gemini-2.0-flash", "gemini/gemini-2.0-flash"),
            ("gemini-1.5-pro", "gemini/gemini-1.5-pro"),
            ("gemini-1.5-flash", "gemini/gemini-1.5-flash"),
        ],
    )
    def test_google_models_prefixed(self, model: str, expected: str) -> None:
        """Google models should be prefixed with gemini/."""
        assert normalize_model(model) == expected

    # Already prefixed models - should NOT be double-prefixed
    @pytest.mark.parametrize(
        "model",
        [
            "anthropic/claude-3-opus-20240229",
            "gemini/gemini-1.5-pro",
            "ollama/llama2",
            "azure/gpt-4",
            "bedrock/anthropic.claude-v2",
        ],
    )
    def test_already_prefixed_unchanged(self, model: str) -> None:
        """Already prefixed models should not be modified."""
        assert normalize_model(model) == model

    # Unknown models - should be returned as-is
    @pytest.mark.parametrize(
        "model",
        [
            "llama2",
            "mistral-7b",
            "some-custom-model",
        ],
    )
    def test_unknown_models_unchanged(self, model: str) -> None:
        """Unknown models should be returned as-is."""
        assert normalize_model(model) == model


class TestModelNormalizationIntegration:
    """Test that model normalization is applied in complete() methods."""

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_complete_normalizes_anthropic_model(self, mock_litellm: MagicMock) -> None:
        """Test that complete() normalizes Anthropic model names."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_litellm.completion.return_value = mock_response

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        # Pass un-prefixed Anthropic model
        provider.complete(messages, model="claude-haiku-4-20250514")

        # Verify litellm received prefixed model
        mock_litellm.completion.assert_called_once()
        call_kwargs = mock_litellm.completion.call_args.kwargs
        assert call_kwargs["model"] == "anthropic/claude-haiku-4-20250514"

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_complete_normalizes_google_model(self, mock_litellm: MagicMock) -> None:
        """Test that complete() normalizes Google model names."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_litellm.completion.return_value = mock_response

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        # Pass un-prefixed Google model
        provider.complete(messages, model="gemini-2.0-flash")

        # Verify litellm received prefixed model
        mock_litellm.completion.assert_called_once()
        call_kwargs = mock_litellm.completion.call_args.kwargs
        assert call_kwargs["model"] == "gemini/gemini-2.0-flash"

    @patch("serix_v2.providers.llm.litellm_provider.litellm")
    def test_complete_with_metadata_normalizes_model(
        self, mock_litellm: MagicMock
    ) -> None:
        """Test that complete_with_metadata() also normalizes models."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.model = "anthropic/claude-haiku-4-20250514"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 5
        mock_response.usage.total_tokens = 15
        mock_litellm.completion.return_value = mock_response

        provider = LiteLLMProvider()
        messages = [{"role": "user", "content": "Test"}]

        # Pass un-prefixed Anthropic model
        provider.complete_with_metadata(messages, model="claude-haiku-4-20250514")

        # Verify litellm received prefixed model
        mock_litellm.completion.assert_called_once()
        call_kwargs = mock_litellm.completion.call_args.kwargs
        assert call_kwargs["model"] == "anthropic/claude-haiku-4-20250514"
