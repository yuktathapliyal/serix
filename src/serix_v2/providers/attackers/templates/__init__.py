"""
Serix v2 - Attack Templates

Pre-defined attack templates for each persona.
Used in STATIC mode and as base for ADAPTIVE mode rewrites.
"""

from .confusion import CONFUSION_TEMPLATES
from .extraction import EXTRACTION_TEMPLATES
from .jailbreak import JAILBREAK_TEMPLATES
from .manipulation import MANIPULATION_TEMPLATES

__all__ = [
    "CONFUSION_TEMPLATES",
    "EXTRACTION_TEMPLATES",
    "JAILBREAK_TEMPLATES",
    "MANIPULATION_TEMPLATES",
]
