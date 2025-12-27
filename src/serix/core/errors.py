"""Exception hierarchy for Serix."""

from __future__ import annotations

from .constants import EXIT_ERROR


class SerixError(Exception):
    """Base exception for all Serix errors."""

    exit_code: int = EXIT_ERROR

    def __init__(self, message: str, exit_code: int | None = None) -> None:
        super().__init__(message)
        if exit_code is not None:
            self.exit_code = exit_code


# ============================================================
# CONFIGURATION ERRORS
# ============================================================
class ConfigError(SerixError):
    """Configuration is invalid or missing."""


class ConfigNotFoundError(ConfigError):
    """Config file not found."""


class ConfigParseError(ConfigError):
    """Config file could not be parsed."""


# ============================================================
# TARGET ERRORS
# ============================================================
class TargetError(SerixError):
    """Target could not be loaded or executed."""


class TargetNotFoundError(TargetError):
    """Target file or function does not exist."""

    def __init__(self, path: str, suggestions: list[str] | None = None) -> None:
        self.path = path
        self.suggestions = suggestions or []
        message = f"Target not found: {path}"
        if suggestions:
            message += "\n  Did you mean?\n    - " + "\n    - ".join(suggestions)
        super().__init__(message)


class TargetLoadError(TargetError):
    """Target exists but could not be loaded."""


class TargetExecutionError(TargetError):
    """Target raised an exception during execution."""


# ============================================================
# API ERRORS
# ============================================================
class APIError(SerixError):
    """Error communicating with external API."""


class APIKeyMissingError(APIError):
    """API key not found in environment."""

    def __init__(self, key_name: str = "OPENAI_API_KEY") -> None:
        self.key_name = key_name
        super().__init__(
            f"API key not found. Set {key_name} environment variable.\n"
            f"  export {key_name}=sk-..."
        )


class APIRateLimitError(APIError):
    """API rate limit exceeded."""


class APITimeoutError(APIError):
    """API request timed out."""


# ============================================================
# ATTACK ERRORS
# ============================================================
class AttackError(SerixError):
    """Error during attack execution."""


class JudgeError(AttackError):
    """Error from the judge model."""


class JudgeParseError(JudgeError):
    """Judge output could not be parsed."""


# ============================================================
# STORAGE ERRORS
# ============================================================
class StorageError(SerixError):
    """Error reading/writing to .serix directory."""


class StorageReadError(StorageError):
    """Could not read from storage."""


class StorageWriteError(StorageError):
    """Could not write to storage."""


# ============================================================
# PLAYBACK ERRORS
# ============================================================
class PlaybackError(SerixError):
    """Error during playback mode."""


class PlaybackExhaustedError(PlaybackError):
    """Recording has fewer responses than the agent requested."""

    def __init__(self, recorded: int, requested: int) -> None:
        self.recorded = recorded
        self.requested = requested
        super().__init__(
            f"Playback exhausted\n"
            f"  Recording contains {recorded} API responses.\n"
            f"  Agent attempted call #{requested}.\n\n"
            f"  This usually means the agent code changed since recording.\n"
            f"  Re-record with: serix dev <script> --capture"
        )
