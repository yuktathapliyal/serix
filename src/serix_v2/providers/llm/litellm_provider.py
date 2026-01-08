"""
Serix v2 - LiteLLM Provider

Multi-provider LLM implementation using LiteLLM.

Law 3: Implements the LLMProvider protocol from core/protocols.py
"""

from __future__ import annotations

import os
from typing import Any

import litellm


def normalize_model(model: str) -> str:
    """Normalize model name for litellm routing.

    Newer model names (claude-haiku-4-*, claude-sonnet-4-*, gemini-2.0-*)
    aren't auto-detected by litellm. This adds provider prefix when needed.

    Args:
        model: Model name (e.g., "claude-haiku-4-20250514")

    Returns:
        Normalized model name with prefix if needed.
    """
    # Already prefixed - return as-is
    if "/" in model:
        return model

    # OpenAI models are auto-detected by litellm
    if model.startswith("gpt-") or model.startswith("o1"):
        return model

    # Anthropic models need prefix for newer names
    if model.startswith("claude"):
        return f"anthropic/{model}"

    # Google models need prefix
    if model.startswith("gemini"):
        return f"gemini/{model}"

    # Unknown - return as-is (let litellm handle)
    return model


class LiteLLMProvider:
    """LLMProvider implementation using LiteLLM for multi-provider support.

    Supports: OpenAI, Anthropic, Ollama, Azure, Bedrock, etc.

    Model format examples:
    - "gpt-4o", "gpt-4o-mini" (OpenAI)
    - "claude-3-opus-20240229", "claude-3-sonnet-20240229" (Anthropic)
    - "ollama/llama2", "ollama/mistral" (Ollama)
    - "azure/gpt-4" (Azure OpenAI)

    LiteLLM automatically routes to the right provider based on model name.

    The LLMProvider protocol requires:
    - complete(messages, model, temperature) -> str
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        drop_params: bool = True,
        verbose: bool = False,
    ) -> None:
        """Initialize the LiteLLM provider.

        Args:
            api_key: Optional API key. If not provided, LiteLLM will use
                     environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
            drop_params: If True, drop unsupported params for each provider.
            verbose: If True, enable LiteLLM verbose logging.
        """
        if api_key:
            # Set for OpenAI by default; LiteLLM will use env vars for others
            os.environ.setdefault("OPENAI_API_KEY", api_key)

        # Configure LiteLLM behavior
        litellm.drop_params = drop_params
        if not verbose:
            litellm.suppress_debug_info = True

    def complete(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float = 0.7,
    ) -> str:
        """Send messages to LLM and get completion.

        Args:
            messages: OpenAI-format message list.
                      Each dict has "role" (system/user/assistant) and "content".
            model: Model identifier (e.g., "gpt-4o", "claude-3-opus-20240229").
            temperature: Sampling temperature (0.0-2.0).

        Returns:
            The LLM's response content as a string.

        Raises:
            litellm.exceptions.*: Various LiteLLM exceptions on API errors.
        """
        # Normalize model name for litellm routing (newer models need prefixes)
        normalized_model = normalize_model(model)

        response = litellm.completion(
            model=normalized_model,
            messages=messages,
            temperature=temperature,
        )

        # Extract content from response
        content = response.choices[0].message.content
        return content or ""

    def complete_with_metadata(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Send messages and return full response with metadata.

        This is an extended method beyond the protocol for debugging/logging.

        Args:
            messages: OpenAI-format message list.
            model: Model identifier.
            temperature: Sampling temperature.
            **kwargs: Additional parameters passed to litellm.completion.

        Returns:
            Dict with "content", "model", "usage", and "raw_response".
        """
        # Normalize model name for litellm routing (newer models need prefixes)
        normalized_model = normalize_model(model)

        response = litellm.completion(
            model=normalized_model,
            messages=messages,
            temperature=temperature,
            **kwargs,
        )

        return {
            "content": response.choices[0].message.content or "",
            "model": response.model,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            },
            "raw_response": response,
        }

    def __repr__(self) -> str:
        return "LiteLLMProvider()"
