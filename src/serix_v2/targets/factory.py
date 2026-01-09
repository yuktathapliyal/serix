"""
Serix v2 - Target Factory

Factory function to create the appropriate Target based on the config.

Law 3: Returns a Target protocol implementation
Law 4: Targets are instantiated with their configuration (no globals)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from serix_v2.targets.http_target import HTTPTarget
from serix_v2.targets.python_target import PythonFunctionTarget

if TYPE_CHECKING:
    from serix_v2.core.config import SerixSessionConfig
    from serix_v2.core.protocols import Target


def resolve_target(config: "SerixSessionConfig") -> "Target":
    """Factory function that returns the appropriate Target implementation.

    Determines target type from the target_path:
    - Starts with "http://" or "https://" -> HTTPTarget
    - Contains ":" -> PythonFunctionTarget
    - Otherwise -> Error

    Passes target_name and target_id from config for ID generation precedence:
    - explicit_id (--target-id) > name (--name) > auto-hash from locator

    Args:
        config: The SerixSessionConfig containing target settings.

    Returns:
        A Target implementation (HTTPTarget or PythonFunctionTarget).

    Raises:
        ValueError: If the target_path format is not recognized.
    """
    path = config.target_path

    if path.startswith(("http://", "https://")):
        return HTTPTarget(
            url=path,
            input_field=config.input_field,
            output_field=config.output_field,
            headers=config.headers,
            headers_file=config.headers_file,
            name=config.target_name,  # --name flag
            explicit_id=config.target_id,  # --target-id flag
        )
    elif ":" in path:
        return PythonFunctionTarget(
            locator=path,
            name=config.target_name,  # --name flag
            explicit_id=config.target_id,  # --target-id flag
        )
    else:
        raise ValueError(
            f"Cannot determine target type for: '{path}'. "
            "Expected either:\n"
            "  - HTTP URL: 'http://...' or 'https://...'\n"
            "  - Python path: 'path/to/module.py:function_name' or "
            "'path/to/module.py:ClassName.method_name'"
        )
