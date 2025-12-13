"""SerixClient - OpenAI client wrapper with interception capabilities."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from openai import OpenAI
from openai.types.chat import ChatCompletion
from rich.console import Console

from serix.core.types import (
    RecordedRequest,
    RecordedResponse,
    RecordingSession,
    SerixConfig,
    SerixMode,
)

if TYPE_CHECKING:
    pass

console = Console()

# Global state for the interceptor
_serix_config: SerixConfig | None = None
_recording_session: RecordingSession | None = None
_replay_index: int = 0
_original_openai_class: type[OpenAI] | None = None


def set_serix_config(config: SerixConfig) -> None:
    """Set the global Serix configuration."""
    global _serix_config
    _serix_config = config


def get_serix_config() -> SerixConfig | None:
    """Get the global Serix configuration."""
    return _serix_config


def set_recording_session(session: RecordingSession | None) -> None:
    """Set the global recording session."""
    global _recording_session, _replay_index
    _recording_session = session
    _replay_index = 0


def get_recording_session() -> RecordingSession | None:
    """Get the global recording session."""
    return _recording_session


def set_original_openai_class(cls: type[OpenAI]) -> None:
    """Store the original OpenAI class before patching."""
    global _original_openai_class
    _original_openai_class = cls


def get_original_openai_class() -> type[OpenAI] | None:
    """Get the original (unpatched) OpenAI class."""
    return _original_openai_class


class SerixChatCompletions:
    """Wrapper for chat.completions that intercepts calls."""

    def __init__(self, client: "SerixClient") -> None:
        self._client = client
        # Access parent class's chat via descriptor protocol to avoid circular dependency
        # OpenAI.chat is a cached_property, so we use __get__ directly
        self._original_completions = OpenAI.chat.__get__(
            client, type(client)
        ).completions

    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        stream: bool = False,
        **kwargs: Any,
    ) -> ChatCompletion:
        """Intercept chat.completions.create calls."""
        global _replay_index

        config = get_serix_config()
        session = get_recording_session()

        # Handle streaming - force non-streaming for MVP
        if stream:
            console.print(
                "[yellow]⚠️  Serix MVP only supports non-streaming mode. "
                "Forcing stream=False[/yellow]"
            )
            stream = False

        # Log interception
        if config and config.verbose:
            console.print(
                f"[yellow][INTERCEPTED][/yellow] {model} - {len(messages)} messages"
            )

        # Build request record
        request = RecordedRequest(
            model=model,
            messages=messages,
            tools=kwargs.get("tools"),
            tool_choice=kwargs.get("tool_choice"),
            temperature=kwargs.get("temperature"),
            max_tokens=kwargs.get("max_tokens"),
            extra_kwargs={
                k: v
                for k, v in kwargs.items()
                if k not in ("tools", "tool_choice", "temperature", "max_tokens")
            },
        )

        # Handle different modes
        if config and config.mode == SerixMode.REPLAY:
            return self._handle_replay(request)

        # Make the actual API call
        start_time = time.perf_counter()
        response = self._original_completions.create(
            model=model,
            messages=messages,
            stream=stream,
            **kwargs,
        )
        latency_ms = (time.perf_counter() - start_time) * 1000

        # Record if in record mode
        if config and config.mode == SerixMode.RECORD and session:
            self._record_interaction(request, response, latency_ms)

        # Apply fuzzing mutations if in FUZZ mode
        if config and config.mode == SerixMode.FUZZ and config.fuzz:
            from serix.fuzz.engine import FuzzEngine

            engine = FuzzEngine(config.fuzz, verbose=config.verbose)
            fuzz_result = engine.maybe_mutate(response)

            # Re-raise any injected errors
            if fuzz_result.error_raised:
                raise fuzz_result.error_raised

            # Return mutated response
            if fuzz_result.mutated_response:
                return fuzz_result.mutated_response

        return response

    def _handle_replay(self, request: RecordedRequest) -> ChatCompletion:
        """Return cached response from recording session."""
        global _replay_index

        session = get_recording_session()
        if not session or _replay_index >= len(session.interactions):
            raise RuntimeError(
                f"Replay exhausted: requested interaction {_replay_index}, "
                f"but only {len(session.interactions) if session else 0} recorded"
            )

        interaction = session.interactions[_replay_index]
        _replay_index += 1

        config = get_serix_config()
        if config and config.verbose:
            console.print(
                f"[cyan][REPLAY {interaction.index}][/cyan] "
                f"Returning cached response"
            )

        # Reconstruct ChatCompletion from recorded data
        return ChatCompletion.model_validate(interaction.response.model_dump())

    def _record_interaction(
        self,
        request: RecordedRequest,
        response: ChatCompletion,
        latency_ms: float,
    ) -> None:
        """Record an interaction to the session."""
        session = get_recording_session()
        if not session:
            return

        recorded_response = RecordedResponse(
            id=response.id,
            model=response.model,
            choices=[choice.model_dump() for choice in response.choices],
            usage=response.usage.model_dump() if response.usage else None,
            created=response.created,
            object=response.object,
        )

        session.add_interaction(request, recorded_response, latency_ms)

        config = get_serix_config()
        if config and config.verbose:
            console.print(
                f"[green][RECORDED {len(session.interactions) - 1}][/green] "
                f"{latency_ms:.0f}ms"
            )


class SerixChat:
    """Wrapper for the chat namespace."""

    def __init__(self, client: "SerixClient") -> None:
        self.completions = SerixChatCompletions(client)


class SerixClient(OpenAI):
    """
    OpenAI client wrapper that intercepts API calls.

    This class mimics the OpenAI client interface but intercepts
    chat.completions.create calls for recording, replay, and fuzzing.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._serix_chat = SerixChat(self)

    @property
    def chat(self) -> SerixChat:  # type: ignore[override]
        """Return the intercepting chat wrapper."""
        return self._serix_chat
