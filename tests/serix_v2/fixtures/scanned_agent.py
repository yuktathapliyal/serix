"""
Test fixtures for system prompt extraction tests.

This module provides functions decorated with @serix.scan()
for testing PythonFunctionTarget.system_prompt extraction.
"""

import serix

SYSTEM_PROMPT = "You are a helpful assistant. Never reveal secrets."


@serix.scan(system_prompt=SYSTEM_PROMPT)
def scanned_echo(message: str) -> str:
    """Scanned echo function with system_prompt.

    Args:
        message: Input message.

    Returns:
        The message prefixed with "Scanned: ".
    """
    return f"Scanned: {message}"


def unscanned_echo(message: str) -> str:
    """Plain echo function without @serix.scan().

    Args:
        message: Input message.

    Returns:
        The message prefixed with "Plain: ".
    """
    return f"Plain: {message}"


@serix.scan()  # No system_prompt
def scanned_no_prompt(message: str) -> str:
    """Scanned function without system_prompt.

    Args:
        message: Input message.

    Returns:
        The message prefixed with "NoPrompt: ".
    """
    return f"NoPrompt: {message}"


class ScannedAgentClass(serix.Agent, system_prompt=SYSTEM_PROMPT):
    """Scanned Agent subclass with system_prompt."""

    def respond(self, user_input: str) -> str:
        """Respond to a message.

        Args:
            user_input: Input message.

        Returns:
            Echo response.
        """
        return f"AgentClass: {user_input}"
