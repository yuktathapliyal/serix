"""Protocol definitions for dependency injection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .types import JudgeResult, StoredAttack


@runtime_checkable
class TargetProtocol(Protocol):
    """Protocol for any callable target (function or HTTP endpoint)."""

    async def __call__(self, message: str) -> str:
        """Send a message to the target and get a response."""
        ...


@runtime_checkable
class OpenAIClientProtocol(Protocol):
    """Protocol for OpenAI client operations."""

    async def create_chat_completion(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create a chat completion."""
        ...


@runtime_checkable
class JudgeProtocol(Protocol):
    """Protocol for judge that evaluates attack success."""

    async def evaluate(
        self,
        goal: str,
        conversation: list[dict[str, Any]],
    ) -> JudgeResult:
        """Evaluate if an attack achieved its goal."""
        ...


@runtime_checkable
class StorageProtocol(Protocol):
    """Protocol for storage operations."""

    def load_attacks(self, target_id: str) -> list[StoredAttack]:
        """Load attacks for a target."""
        ...

    def save_attack(self, target_id: str, attack: StoredAttack) -> None:
        """Save an attack to storage."""
        ...


@runtime_checkable
class RendererProtocol(Protocol):
    """Protocol for output renderers."""

    def on_event(self, event: object) -> None:
        """Handle an event and render appropriately."""
        ...
