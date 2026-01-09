"""
Serix v2 Config - TOML Loader

Functions for finding and loading serix.toml or pyproject.toml [tool.serix].
Uses Python 3.11+ stdlib tomllib for parsing.
"""

import tomllib
from pathlib import Path

from serix_v2.core.constants import CONFIG_FILENAME, PYPROJECT_SECTION
from serix_v2.core.errors import ConfigParseError

from .models import TomlConfig


def find_config_file(start_dir: Path | None = None) -> Path | None:
    """
    Walk up directory tree to find serix.toml or pyproject.toml [tool.serix].

    Args:
        start_dir: Directory to start searching. Defaults to cwd.

    Returns:
        Path to config file, or None if not found.

    Search order per directory:
        1. serix.toml (highest priority)
        2. pyproject.toml with [tool.serix] section

    Example:
        >>> find_config_file(Path("/project/src"))
        PosixPath('/project/serix.toml')
    """
    if start_dir is None:
        start_dir = Path.cwd()

    current = start_dir.resolve()

    while True:
        # Check for serix.toml first (highest priority)
        serix_toml = current / CONFIG_FILENAME
        if serix_toml.exists():
            return serix_toml

        # Check for pyproject.toml with [tool.serix] section
        pyproject_toml = current / "pyproject.toml"
        if pyproject_toml.exists() and _has_serix_section(pyproject_toml):
            return pyproject_toml

        # Move to parent directory
        parent = current.parent
        if parent == current:
            # Reached filesystem root
            return None
        current = parent


def _has_serix_section(pyproject_path: Path) -> bool:
    """
    Check if pyproject.toml contains [tool.serix] section.

    Args:
        pyproject_path: Path to pyproject.toml file.

    Returns:
        True if [tool.serix] section exists, False otherwise.
    """
    try:
        content = pyproject_path.read_bytes()
        data = tomllib.loads(content.decode("utf-8"))

        # Navigate to tool.serix section
        parts = PYPROJECT_SECTION.split(".")
        current = data
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                return False
            current = current[part]

        return True
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        # Invalid TOML or encoding - treat as no section
        return False


def load_toml_config(config_path: Path | None = None) -> tuple[TomlConfig, Path | None]:
    """
    Load and parse TOML configuration file.

    Args:
        config_path: Explicit path to config file. If None, searches for one.

    Returns:
        Tuple of (TomlConfig, config_dir):
        - TomlConfig with parsed values (empty if no file found)
        - config_dir: Directory containing the config file (for path resolution)

    Raises:
        ConfigParseError: If file exists but cannot be parsed.

    Note:
        File type determines root extraction:
        - serix.toml: Uses entire file as root
        - pyproject.toml: Extracts data["tool"]["serix"] section as root

    Example:
        # serix.toml (entire file is config)
        [target]
        path = "agent.py:fn"

        # pyproject.toml (only [tool.serix] section used)
        [tool.serix]
        verbose = true

        [tool.serix.target]
        path = "agent.py:fn"
    """
    # Find config file if not provided
    if config_path is None:
        config_path = find_config_file()

    # No config file found - return empty config
    if config_path is None:
        return TomlConfig(), None

    # Parse the TOML file
    try:
        content = config_path.read_bytes()
        data = tomllib.loads(content.decode("utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ConfigParseError(
            path=str(config_path),
            message=str(e),
        )
    except UnicodeDecodeError as e:
        raise ConfigParseError(
            path=str(config_path),
            message=f"Invalid encoding: {e}",
        )

    # Extract appropriate root based on file type
    if config_path.name == "pyproject.toml":
        data = _extract_pyproject_section(data)

    # Parse into Pydantic model
    try:
        config = TomlConfig.model_validate(data)
    except Exception as e:
        raise ConfigParseError(
            path=str(config_path),
            message=f"Validation error: {e}",
        )

    config_dir = config_path.parent
    return config, config_dir


def _extract_pyproject_section(data: dict) -> dict:
    """
    Extract [tool.serix] section from pyproject.toml data.

    Args:
        data: Parsed pyproject.toml as dict.

    Returns:
        The tool.serix section, or empty dict if not found.
    """
    parts = PYPROJECT_SECTION.split(".")
    current = data

    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return {}
        current = current[part]

    if isinstance(current, dict):
        return current
    return {}
