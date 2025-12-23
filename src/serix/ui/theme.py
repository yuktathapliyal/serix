"""Serix visual theme - colors, glyphs, and console configuration.

Design tokens for Serix's premium, YC-ready visual identity.
Uses color sparingly and semantically for easy scanning.
"""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.theme import Theme

# =============================================================================
# Theme Tokens
# =============================================================================

SERIX_THEME = Theme(
    {
        "serix.brand": "bold magenta",  # SERIX wordmark, headings (violet/purple)
        "serix.label": "cyan",  # Key labels (Target, Mode, Goal)
        "serix.muted": "dim",  # Secondary text, descriptions
        "serix.ok": "green",  # Success, defended
        "serix.bad": "red",  # Failure, exploited (use sparingly)
        "serix.warn": "yellow",  # Warnings (rare)
        "serix.title": "white",  # Primary content text
        "serix.rule": "dim",  # Separators
    }
)

# =============================================================================
# Glyphs
# =============================================================================

PREFIX = "\u203a"  # › - Key/value line prefix
SEPARATOR = "\u2500" * 60  # ─ - Thin horizontal rule
SUCCESS = "\u2713"  # ✓ - Checkmark
FAILURE = "\u2717"  # ✗ - X mark
BULLET = "\u2022"  # • - Bullet point

# =============================================================================
# Tagline
# =============================================================================

TAGLINE = "The Immune System for AI Agents"

# =============================================================================
# Console Factory
# =============================================================================


def get_console(force_terminal: bool | None = None) -> Console:
    """Get a configured Rich console with Serix theme.

    Args:
        force_terminal: Override terminal detection.
            True = force terminal output (colors enabled)
            False = force non-terminal output (no colors)
            None = auto-detect (default)

    Returns:
        Rich Console configured with Serix theme
    """
    return Console(
        theme=SERIX_THEME,
        force_terminal=force_terminal,
        soft_wrap=True,
        highlight=False,
    )


def is_interactive() -> bool:
    """Check if running in interactive terminal (not CI).

    Returns True for local dev (terminal with user input possible).
    Returns False for CI, piped output, or non-TTY environments.
    """
    # Check for CI environment variables
    if os.environ.get("CI"):
        return False
    if os.environ.get("GITHUB_ACTIONS"):
        return False
    if os.environ.get("JENKINS_URL"):
        return False
    if os.environ.get("GITLAB_CI"):
        return False

    # Check for TTY
    return sys.stdout.isatty() and sys.stdin.isatty()
