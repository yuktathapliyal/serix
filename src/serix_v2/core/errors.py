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
