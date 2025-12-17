"""Attack personas for adaptive red team attacks.

Personas: JailbreakerPersona, ExtractorPersona, ConfuserPersona, ManipulatorPersona
"""

from serix.fuzz.personas.base import (
    AttackContext,
    AttackPayload,
    AttackPersona,
    PersonaConfig,
)
from serix.fuzz.personas.confuser import ConfuserPersona
from serix.fuzz.personas.extractor import ExtractorPersona
from serix.fuzz.personas.jailbreaker import JailbreakerPersona
from serix.fuzz.personas.manipulator import ManipulatorPersona

__all__ = [
    # Base types
    "AttackContext",
    "AttackPayload",
    "AttackPersona",
    "PersonaConfig",
    # Personas
    "JailbreakerPersona",
    "ExtractorPersona",
    "ConfuserPersona",
    "ManipulatorPersona",
]


# Mapping of persona names to classes for factory functions
PERSONA_REGISTRY: dict[str, type[AttackPersona]] = {
    "jailbreaker": JailbreakerPersona,
    "extractor": ExtractorPersona,
    "confuser": ConfuserPersona,
    "manipulator": ManipulatorPersona,
}


def get_persona_class(name: str) -> type[AttackPersona] | None:
    """Get persona class by name.

    Args:
        name: Persona name (jailbreaker, extractor, confuser, manipulator)

    Returns:
        Persona class or None if not found
    """
    return PERSONA_REGISTRY.get(name.lower())


def list_personas() -> list[str]:
    """List all available persona names.

    Returns:
        List of persona names
    """
    return list(PERSONA_REGISTRY.keys())
