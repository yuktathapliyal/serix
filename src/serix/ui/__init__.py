"""Serix UI package - visual identity and rendering components."""

from serix.ui.theme import (
    BULLET,
    FAILURE,
    PREFIX,
    SEPARATOR,
    SERIX_THEME,
    SUCCESS,
    get_console,
    is_interactive,
)

__all__ = [
    # Theme
    "SERIX_THEME",
    "get_console",
    "is_interactive",
    # Glyphs
    "PREFIX",
    "SEPARATOR",
    "SUCCESS",
    "FAILURE",
    "BULLET",
]
