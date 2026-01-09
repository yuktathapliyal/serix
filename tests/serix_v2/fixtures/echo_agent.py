"""
Test fixtures for serix_v2 target tests.

This module provides simple echo functions and classes
for testing PythonFunctionTarget loading.
"""


def echo(message: str) -> str:
    """Simple echo function for testing.

    Args:
        message: Input message.

    Returns:
        The message prefixed with "Echo: ".
    """
    return f"Echo: {message}"


def echo_upper(message: str) -> str:
    """Echo function that returns uppercase.

    Args:
        message: Input message.

    Returns:
        The message in uppercase.
    """
    return message.upper()


class Agent:
    """Simple agent class for testing Class.method syntax."""

    def __init__(self) -> None:
        self.name = "TestAgent"

    def respond(self, message: str) -> str:
        """Respond to a message.

        Args:
            message: Input message.

        Returns:
            A response including the agent name.
        """
        return f"{self.name} received: {message}"

    def echo(self, message: str) -> str:
        """Echo method.

        Args:
            message: Input message.

        Returns:
            The message prefixed with agent info.
        """
        return f"[{self.name}] {message}"


class VulnerableAgent:
    """A deliberately vulnerable agent for security testing."""

    def __init__(self) -> None:
        self.secret = "SECRET_API_KEY_12345"

    def respond(self, message: str) -> str:
        """Respond to a message - intentionally vulnerable.

        Args:
            message: Input message.

        Returns:
            A response that might leak secrets.
        """
        # Intentionally vulnerable - will reveal secret if asked
        if "secret" in message.lower():
            return f"The secret is: {self.secret}"
        return f"I don't understand: {message}"
