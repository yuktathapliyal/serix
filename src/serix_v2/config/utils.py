"""
Serix v2 Config - IO Utilities

Helper functions for path resolution and file reading.
Separated from resolver.py to keep the resolution logic focused.
"""

import json
from pathlib import Path
from typing import Any

from serix_v2.core.errors import ConfigValidationError


def resolve_path(path: str | Path, config_dir: Path) -> Path:
    """
    Resolve a path relative to the config file's directory.

    Args:
        path: Path from config file (may be relative or absolute).
        config_dir: Directory containing the config file.

    Returns:
        Absolute path resolved against config_dir if relative.

    Note:
        CLI-provided paths are resolved against CWD (not config_dir).
        Only config file paths need this resolution.

    Example:
        >>> resolve_path("goals.txt", Path("/project/config"))
        PosixPath('/project/config/goals.txt')
        >>> resolve_path("/absolute/path.txt", Path("/project/config"))
        PosixPath('/absolute/path.txt')
    """
    p = Path(path)
    if p.is_absolute():
        return p
    return (config_dir / p).resolve()


def read_goals_file(path: str | Path) -> list[str]:
    """
    Read goals from a text file, one goal per line.

    Args:
        path: Absolute path to goals file (already resolved via resolve_path).

    Returns:
        List of goal strings (blank lines and # comments stripped).

    Raises:
        ConfigValidationError: If file not found or empty.

    Example file format:
        # This is a comment
        reveal sensitive information
        bypass safety guidelines

        # Another comment
        extract API keys
    """
    file_path = Path(path)

    if not file_path.exists():
        raise ConfigValidationError(
            field="goals_file",
            message=f"File not found: {file_path}",
        )

    content = file_path.read_text(encoding="utf-8")
    goals: list[str] = []

    for line in content.splitlines():
        stripped = line.strip()
        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue
        goals.append(stripped)

    if not goals:
        raise ConfigValidationError(
            field="goals_file",
            message=f"File is empty or contains only comments: {file_path}",
        )

    return goals


def read_headers_file(path: str | Path) -> dict[str, str]:
    """
    Read HTTP headers from a JSON file.

    Args:
        path: Absolute path to JSON file (already resolved via resolve_path).

    Returns:
        Dict of header_name -> header_value.

    Raises:
        ConfigValidationError: If file not found or invalid JSON.

    Example file format:
        {
            "Authorization": "Bearer sk-...",
            "X-Custom-Header": "value"
        }
    """
    file_path = Path(path)

    if not file_path.exists():
        raise ConfigValidationError(
            field="headers_file",
            message=f"File not found: {file_path}",
        )

    try:
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ConfigValidationError(
            field="headers_file",
            message=f"Invalid JSON in {file_path}: {e}",
        )

    if not isinstance(data, dict):
        raise ConfigValidationError(
            field="headers_file",
            message=f"Expected JSON object, got {type(data).__name__}: {file_path}",
        )

    # Ensure all values are strings
    headers: dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(value, str):
            raise ConfigValidationError(
                field="headers_file",
                message=f"Header '{key}' value must be string, got {type(value).__name__}",
            )
        headers[str(key)] = value

    return headers


def parse_env_bool(value: str) -> bool:
    """
    Parse environment variable string to boolean.

    Truthy: "1", "true", "yes", "on" (case-insensitive)
    Falsy: "0", "false", "no", "off", "" (case-insensitive)

    Args:
        value: Raw string from os.environ.

    Returns:
        Boolean interpretation of the string.

    Raises:
        ValueError: If value is not a recognized boolean string.
    """
    lower = value.lower().strip()

    if lower in ("1", "true", "yes", "on"):
        return True
    if lower in ("0", "false", "no", "off", ""):
        return False

    raise ValueError(f"Cannot parse '{value}' as boolean")


def parse_env_value(value: str, target_type: type) -> Any:
    """
    Parse environment variable string to target type.

    Args:
        value: Raw string from os.environ.
        target_type: Expected type (str, int, float, bool).

    Returns:
        Parsed value of target_type.

    Raises:
        ValueError: If value cannot be parsed to target_type.
    """
    if target_type is str:
        return value

    if target_type is bool:
        return parse_env_bool(value)

    if target_type is int:
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"Cannot parse '{value}' as int")

    if target_type is float:
        try:
            return float(value)
        except ValueError:
            raise ValueError(f"Cannot parse '{value}' as float")

    raise ValueError(f"Unsupported target type: {target_type}")
