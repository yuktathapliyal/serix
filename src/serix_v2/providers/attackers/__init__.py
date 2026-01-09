"""
Serix v2 - Attacker Providers

Attack persona implementations that conform to the Attacker protocol.
"""

from __future__ import annotations

from serix_v2.core.contracts import AttackMode, Persona
from serix_v2.core.protocols import Attacker, LLMProvider

from .base import BaseAttacker
from .confuser import ConfuserAttacker
from .extractor import ExtractorAttacker
from .jailbreaker import JailbreakerAttacker
from .manipulator import ManipulatorAttacker

__all__ = [
    "BaseAttacker",
    "ConfuserAttacker",
    "ExtractorAttacker",
    "JailbreakerAttacker",
    "ManipulatorAttacker",
    "create_attacker",
]


def create_attacker(
    persona: Persona,
    llm_provider: LLMProvider,
    mode: AttackMode = AttackMode.ADAPTIVE,
    model: str = "gpt-4o-mini",
) -> Attacker:
    """
    Factory function to create an attacker for a given persona.

    Args:
        persona: The attack persona (JAILBREAKER, EXTRACTOR, etc.)
        llm_provider: LLM provider for adaptive mode.
        mode: STATIC (templates only) or ADAPTIVE (LLM rewriting).
        model: Model to use for adaptive mode.

    Returns:
        An Attacker instance.

    Raises:
        ValueError: If persona is not yet implemented.
    """
    # Type: concrete attacker classes (not BaseAttacker which is abstract)
    attacker_map: dict[
        Persona,
        type[JailbreakerAttacker]
        | type[ExtractorAttacker]
        | type[ConfuserAttacker]
        | type[ManipulatorAttacker],
    ] = {
        Persona.JAILBREAKER: JailbreakerAttacker,
        Persona.EXTRACTOR: ExtractorAttacker,
        Persona.CONFUSER: ConfuserAttacker,
        Persona.MANIPULATOR: ManipulatorAttacker,
    }

    attacker_cls = attacker_map.get(persona)
    if attacker_cls is None:
        raise ValueError(f"Persona {persona} not yet implemented")

    return attacker_cls(llm_provider, model, mode)
