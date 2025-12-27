"""OpenAI client wrapper with rate limiting and retry logic.

Provides thread-safe access to OpenAI API with:
- Semaphore-based concurrency limiting (Tier 1/2 protection)
- Exponential backoff retry on rate limits
- Clean interface for dependency injection
"""

from __future__ import annotations

import os
import threading
import time
from typing import TYPE_CHECKING, Any

from openai import OpenAI, RateLimitError

from ..core.constants import DEFAULT_JUDGE_MODEL
from ..core.errors import APIKeyMissingError, APIRateLimitError

if TYPE_CHECKING:
    pass


class OpenAIAdapter:
    """Thread-safe OpenAI client wrapper with rate limiting.

    Uses a semaphore to limit concurrent API calls, preventing
    Tier 1/2 rate limit errors when running multiple personas
    in parallel.

    Attributes:
        raw_client: The underlying OpenAI client for persona compatibility
    """

    _semaphore: threading.Semaphore

    def __init__(
        self,
        api_key: str | None = None,
        max_concurrent: int = 2,
        max_retries: int = 3,
    ) -> None:
        """Initialize the adapter.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            max_concurrent: Max concurrent API calls (default: 2 for Tier 1)
            max_retries: Max retry attempts on rate limit

        Raises:
            APIKeyMissingError: If no API key found
        """
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise APIKeyMissingError()

        self._client = OpenAI(api_key=self._api_key)
        self._semaphore = threading.Semaphore(max_concurrent)
        self._max_retries = max_retries

    @property
    def raw_client(self) -> OpenAI:
        """Get the underlying OpenAI client.

        Used for persona compatibility - personas expect raw OpenAI client.
        """
        return self._client

    def create_chat_completion(
        self,
        messages: list[dict[str, Any]],
        model: str = DEFAULT_JUDGE_MODEL,
        temperature: float = 0.7,
        max_tokens: int = 500,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create chat completion with rate limiting and retry.

        Args:
            messages: Chat messages
            model: Model to use
            temperature: Sampling temperature
            max_tokens: Max tokens in response
            **kwargs: Additional OpenAI parameters

        Returns:
            Dict with 'content', 'model', and 'usage' keys

        Raises:
            APIRateLimitError: If rate limit exceeded after retries
        """
        with self._semaphore:
            last_error: Exception | None = None

            for attempt in range(self._max_retries):
                try:
                    response = self._client.chat.completions.create(
                        model=model,
                        messages=messages,  # type: ignore[arg-type]
                        temperature=temperature,
                        max_tokens=max_tokens,
                        **kwargs,
                    )
                    return {
                        "content": response.choices[0].message.content or "",
                        "model": response.model,
                        "usage": response.usage.model_dump() if response.usage else {},
                    }
                except RateLimitError as e:
                    last_error = e
                    if attempt < self._max_retries - 1:
                        # Exponential backoff: 1s, 2s, 4s
                        time.sleep(2**attempt)

            # All retries exhausted
            raise APIRateLimitError(
                f"Rate limit exceeded after {self._max_retries} retries. "
                f"Last error: {last_error}"
            )
