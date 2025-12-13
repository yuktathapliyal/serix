"""Rule-based mutations for fuzzing API responses."""

from __future__ import annotations

import random
import time
from abc import ABC, abstractmethod

import httpx
from openai import APIError, RateLimitError
from openai.types.chat import ChatCompletion
from rich.console import Console

console = Console()


def _create_mock_request() -> httpx.Request:
    """Create a mock request for injected errors."""
    return httpx.Request("POST", "https://api.openai.com/v1/chat/completions")


def _create_mock_response(status_code: int) -> httpx.Response:
    """Create a mock response for injected errors."""
    request = _create_mock_request()
    return httpx.Response(status_code=status_code, request=request)


class Mutation(ABC):
    """Base class for mutations."""

    name: str = "base"

    @abstractmethod
    def apply(
        self,
        response: ChatCompletion,
        verbose: bool = False,
    ) -> ChatCompletion:
        """Apply the mutation to a response."""
        pass

    @abstractmethod
    def should_apply(self, probability: float) -> bool:
        """Determine if this mutation should be applied."""
        pass


class LatencyMutation(Mutation):
    """Inject artificial latency before returning response."""

    name = "latency"

    def __init__(self, delay_seconds: float = 5.0) -> None:
        self.delay_seconds = delay_seconds

    def apply(
        self,
        response: ChatCompletion,
        verbose: bool = False,
    ) -> ChatCompletion:
        """Sleep for the configured duration."""
        if verbose:
            console.print(
                f"[yellow][FUZZ: LATENCY][/yellow] Injecting {self.delay_seconds}s delay"
            )
        time.sleep(self.delay_seconds)
        return response

    def should_apply(self, probability: float) -> bool:
        return random.random() < probability


class ErrorMutation(Mutation):
    """Raise API errors instead of returning response."""

    name = "error"

    def __init__(self, error_codes: list[int] | None = None) -> None:
        self.error_codes = error_codes or [500, 503, 429]

    def apply(
        self,
        response: ChatCompletion,
        verbose: bool = False,
    ) -> ChatCompletion:
        """Raise a random API error."""
        error_code = random.choice(self.error_codes)

        if verbose:
            console.print(f"[yellow][FUZZ: ERROR][/yellow] Injecting HTTP {error_code}")

        if error_code == 429:
            raise RateLimitError(
                message="Rate limit exceeded (injected by Serix)",
                response=_create_mock_response(429),
                body={"error": {"message": "Rate limit exceeded"}},
            )
        else:
            raise APIError(
                message=f"HTTP {error_code} (injected by Serix)",
                request=_create_mock_request(),
                body={"error": {"message": f"HTTP {error_code}"}},
            )

    def should_apply(self, probability: float) -> bool:
        return random.random() < probability


class JsonCorruptionMutation(Mutation):
    """Corrupt the JSON response in various ways."""

    name = "json_corruption"

    def __init__(self) -> None:
        self.corruption_strategies = [
            self._remove_key,
            self._truncate_content,
            self._wrong_type,
            self._null_value,
        ]

    def apply(
        self,
        response: ChatCompletion,
        verbose: bool = False,
    ) -> ChatCompletion:
        """Apply a random corruption strategy."""
        strategy = random.choice(self.corruption_strategies)

        if verbose:
            console.print(f"[yellow][FUZZ: JSON][/yellow] Applying {strategy.__name__}")

        return strategy(response)

    def should_apply(self, probability: float) -> bool:
        return random.random() < probability

    def _remove_key(self, response: ChatCompletion) -> ChatCompletion:
        """Remove a key from the response by setting usage to None."""
        # Create a modified copy
        data = response.model_dump()
        data["usage"] = None
        return ChatCompletion.model_validate(data)

    def _truncate_content(self, response: ChatCompletion) -> ChatCompletion:
        """Truncate the message content."""
        data = response.model_dump()
        if data["choices"] and data["choices"][0].get("message", {}).get("content"):
            content = data["choices"][0]["message"]["content"]
            # Truncate to random length
            truncate_at = random.randint(1, max(1, len(content) // 2))
            data["choices"][0]["message"]["content"] = content[:truncate_at]
        return ChatCompletion.model_validate(data)

    def _wrong_type(self, response: ChatCompletion) -> ChatCompletion:
        """Change a value to wrong type (usage tokens to string)."""
        data = response.model_dump()
        if data.get("usage"):
            # This will likely cause validation errors downstream
            data["usage"]["prompt_tokens"] = "not_a_number"  # type: ignore
        return ChatCompletion.model_validate(data)

    def _null_value(self, response: ChatCompletion) -> ChatCompletion:
        """Set content to None."""
        data = response.model_dump()
        if data["choices"]:
            data["choices"][0]["message"]["content"] = None
        return ChatCompletion.model_validate(data)
