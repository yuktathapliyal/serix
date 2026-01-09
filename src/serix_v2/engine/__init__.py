"""
Serix v2 - Engine Package

The engine contains the core attack logic without any CLI dependencies.
Law 2: No typer/rich/click imports allowed here.
"""

from .adversary import AdversaryEngine

__all__ = ["AdversaryEngine"]
