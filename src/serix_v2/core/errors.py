"""
Serix v2 - Error Definitions

Centralized error classes for the serix_v2 package.
All custom exceptions are defined here to maintain consistency.
"""


class SerixError(Exception):
    """Base exception for all Serix errors."""

    pass


class ConfigParseError(SerixError):
    """Raised when a config file cannot be parsed (invalid TOML syntax)."""

    def __init__(self, path: str, message: str):
        self.path = path
        self.message = message
        super().__init__(f"Failed to parse config file '{path}': {message}")


class ConfigValidationError(SerixError):
    """Raised when config values are invalid (missing required fields, bad types)."""

    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"Config validation error for '{field}': {message}")


class TargetUnreachableError(SerixError):
    """Raised when the target cannot be reached during preflight check.

    This error is raised early in the workflow when the target fails
    to respond to a simple test message. This prevents wasting time
    and resources on a target that isn't working.
    """

    def __init__(self, target_id: str, locator: str, reason: str):
        self.target_id = target_id
        self.locator = locator
        self.reason = reason
        super().__init__(
            f"Target unreachable (id={target_id}, locator={locator}): {reason}"
        )


class TargetCredentialError(SerixError):
    """Raised when target fails due to missing or invalid API credentials.

    This error helps users understand that the TARGET (not Serix) needs
    API credentials. This is especially confusing when the user is using
    a different provider for Serix vs their target.
    """

    def __init__(self, target_id: str, locator: str, original_error: str):
        self.target_id = target_id
        self.locator = locator
        self.original_error = original_error
        self.detected_provider = self._detect_provider(original_error)
        super().__init__(
            f"Target requires API credentials (id={target_id}): {original_error}"
        )

    @staticmethod
    def _detect_provider(error_msg: str) -> str | None:
        """Detect which provider the target likely needs."""
        error_lower = error_msg.lower()
        if "openai" in error_lower or "gpt" in error_lower:
            return "openai"
        elif "anthropic" in error_lower or "claude" in error_lower:
            return "anthropic"
        elif "google" in error_lower or "gemini" in error_lower:
            return "google"
        return None
