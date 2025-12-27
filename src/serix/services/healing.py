"""Healing service for generating security patches.

Wraps the HealingEngine to work with Sprint 1+ AttackResult types,
emit events for the rendering layer, and heuristically find system
prompts in Python targets for better patch quality.
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any

from ..core.events import (
    EventListener,
    HealingGeneratedEvent,
    HealingStartedEvent,
    NullEventListener,
)
from ..heal.engine import AttackContext, HealingEngine
from ..heal.types import HealingResult

if TYPE_CHECKING:
    from openai import OpenAI

    from ..core.types import AttackResult


# Common variable names for system prompts in Python agents
SYSTEM_PROMPT_NAMES = (
    "SYSTEM_PROMPT",
    "system_prompt",
    "SYSTEM_MESSAGE",
    "system_message",
    "SYSTEM",
    "system",
    "PROMPT",
    "prompt",
)


class HealingService:
    """Service for generating healing patches from successful attacks.

    Wraps the HealingEngine to work with Sprint 1 AttackResult types
    and emit events for the rendering layer.

    Features:
    - Converts AttackResult to AttackContext for healing engine
    - Heuristically finds system prompts in Python targets
    - Emits HealingStartedEvent and HealingGeneratedEvent for UI
    - Graceful fallback to tool_fixes if no system prompt found
    """

    def __init__(
        self,
        llm_client: "OpenAI | None" = None,
        event_listener: EventListener | None = None,
    ) -> None:
        """Initialize healing service.

        Args:
            llm_client: OpenAI client for healing engine
            event_listener: Listener for healing events
        """
        self._engine = HealingEngine(llm_client)
        self._events: EventListener = event_listener or NullEventListener()

    def heal(
        self,
        attacks: list["AttackResult"],
        system_prompt: str | None = None,
        target_module: types.ModuleType | None = None,
        target_func: Any | None = None,
    ) -> HealingResult | None:
        """Generate healing for successful attacks.

        Args:
            attacks: List of attack results (filters to successful only)
            system_prompt: Target's system prompt (if known)
            target_module: Python module containing target (for heuristic search)
            target_func: Target function (for docstring extraction)

        Returns:
            HealingResult or None if no successful attacks
        """
        # Filter to successful attacks only
        successful = [a for a in attacks if a.success and a.winning_payload]

        if not successful:
            return None

        # Emit start event
        self._events.on_event(HealingStartedEvent(successful_attacks=len(successful)))

        # Try to find system prompt if not provided
        if not system_prompt:
            system_prompt = self._find_system_prompt(target_module, target_func)

        # Use first successful attack for healing
        # (aggregation of multiple attacks is future enhancement)
        attack = successful[0]

        # Get last agent response from conversation
        agent_response = self._get_agent_response(attack)

        # Create attack context
        context = AttackContext(
            payload=attack.winning_payload or "",
            response=agent_response,
            vulnerability_type=attack.persona.lower(),
        )

        # Generate healing
        if system_prompt:
            result = self._engine.heal(
                system_prompt=system_prompt,
                attack_context=context,
            )
        else:
            # Without system prompt, only tool fixes are possible
            result = HealingResult(
                vulnerability_type=attack.persona.lower(),
                owasp_code=attack.owasp_code or "LLM01",
                confidence=0.7,
                reasoning="System prompt not available for analysis. "
                "Consider providing --system-prompt for better patches.",
            )

        # Emit generated event
        self._events.on_event(
            HealingGeneratedEvent(
                diff=result.text_fix.diff if result.text_fix else "",
                confidence=result.confidence,
                owasp_code=result.owasp_code,
                vulnerability_type=result.vulnerability_type,
                recommendations=[f.recommendation for f in result.tool_fixes],
            )
        )

        return result

    def _find_system_prompt(
        self,
        module: types.ModuleType | None,
        func: Any | None,
    ) -> str | None:
        """Heuristically find system prompt in target module.

        Searches for:
        1. Common variable names (SYSTEM_PROMPT, system_message, etc.)
        2. Function docstring (may contain prompt-like instructions)

        Args:
            module: Python module to search
            func: Target function (for docstring)

        Returns:
            System prompt string if found, None otherwise
        """
        # Try common variable names in module
        if module:
            for name in SYSTEM_PROMPT_NAMES:
                if hasattr(module, name):
                    value = getattr(module, name)
                    if isinstance(value, str) and len(value) > 20:
                        return value

        # Try function docstring
        if func and hasattr(func, "__doc__") and func.__doc__:
            docstring = func.__doc__.strip()
            # Only use docstring if it looks like a prompt (>50 chars, has instructions)
            if len(docstring) > 50 and any(
                keyword in docstring.lower()
                for keyword in ("you are", "assistant", "help", "respond", "answer")
            ):
                return docstring

        return None

    def _get_agent_response(self, attack: "AttackResult") -> str:
        """Extract last agent response from conversation.

        Args:
            attack: Attack result with conversation

        Returns:
            Last agent response or empty string
        """
        if not attack.conversation:
            return ""

        for msg in reversed(attack.conversation):
            if msg.get("role") == "agent":
                return msg.get("content", "")

        return ""
