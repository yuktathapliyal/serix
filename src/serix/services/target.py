"""Target loading service.

Handles loading and validation of attack targets:
- Python functions (path/to/file.py:function_name)
- HTTP endpoints (http://... or https://...)

Fixes BUG-003: Validates file exists before attempting to run.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.errors import TargetLoadError, TargetNotFoundError
from ..core.target import DecoratorTarget, HttpTarget, Target

if TYPE_CHECKING:
    pass


class TargetService:
    """Service for loading and validating targets.

    Provides static methods for target loading with proper error
    handling and validation.
    """

    @staticmethod
    def load(
        target_path: str,
        verbose: bool = False,
        # HTTP options
        input_field: str = "message",
        output_field: str = "response",
        headers: dict[str, str] | None = None,
    ) -> Target:
        """Load a target from a path string.

        Supports:
        - Python functions: "path/to/file.py:function_name"
        - HTTP endpoints: "http://..." or "https://..."

        Args:
            target_path: Path to target (file:function or URL)
            verbose: Enable verbose mode
            input_field: Input field name for HTTP targets
            output_field: Output field name for HTTP targets
            headers: HTTP headers for HTTP targets

        Returns:
            Target instance ready for attacks

        Raises:
            TargetNotFoundError: If file or function doesn't exist
            TargetLoadError: If target can't be loaded
        """
        # HTTP targets
        if target_path.startswith(("http://", "https://")):
            return TargetService._load_http_target(
                target_path,
                input_field=input_field,
                output_field=output_field,
                headers=headers,
                verbose=verbose,
            )

        # Python targets
        return TargetService._load_python_target(target_path, verbose=verbose)

    @staticmethod
    def _load_http_target(
        url: str,
        input_field: str,
        output_field: str,
        headers: dict[str, str] | None,
        verbose: bool,
    ) -> HttpTarget:
        """Load an HTTP endpoint target."""
        target = HttpTarget(
            url=url,
            input_field=input_field,
            output_field=output_field,
            headers=headers or {},
            verbose=verbose,
        )
        # Setup initializes the HTTP client
        target.setup()
        return target

    @staticmethod
    def _load_python_target(
        target_path: str,
        verbose: bool,
    ) -> Target:
        """Load a Python function target.

        Format: "path/to/file.py:function_name"

        Raises:
            TargetLoadError: If format is invalid or module can't load
            TargetNotFoundError: If file or function doesn't exist
        """
        # Parse path
        if ":" not in target_path:
            raise TargetLoadError(
                f"Invalid target format: {target_path}\n"
                f"Expected: path/to/file.py:function_name"
            )

        file_path, func_name = target_path.rsplit(":", 1)
        path = Path(file_path)

        # BUG-003: Validate file exists BEFORE running
        if not path.exists():
            # Try to find similar files for suggestions
            suggestions = TargetService._find_similar_files(path)
            raise TargetNotFoundError(str(path), suggestions=suggestions)

        if not path.is_file():
            raise TargetNotFoundError(
                str(path),
                suggestions=[f"{path} is a directory, not a file"],
            )

        # Load the module
        try:
            spec = importlib.util.spec_from_file_location("target_module", path)
            if spec is None or spec.loader is None:
                raise TargetLoadError(f"Could not load module: {path}")

            module = importlib.util.module_from_spec(spec)

            # Add script directory to path for imports
            script_dir = str(path.parent.resolve())
            if script_dir not in sys.path:
                sys.path.insert(0, script_dir)

            spec.loader.exec_module(module)
        except TargetLoadError:
            raise
        except Exception as e:
            raise TargetLoadError(f"Failed to load module {path}: {e}")

        # Get the function
        if not hasattr(module, func_name):
            available = [
                name
                for name in dir(module)
                if callable(getattr(module, name)) and not name.startswith("_")
            ]
            suggestions = []
            if available:
                suggestions.append(f"Available functions: {', '.join(available)}")
            raise TargetNotFoundError(f"{path}:{func_name}", suggestions=suggestions)

        func = getattr(module, func_name)
        if not callable(func):
            raise TargetLoadError(f"{func_name} is not callable")

        return DecoratorTarget(func=func, verbose=verbose)

    @staticmethod
    def _find_similar_files(path: Path) -> list[str]:
        """Find similar files for 'did you mean?' suggestions.

        Uses basic stem matching to find candidates.
        """
        suggestions: list[str] = []
        parent = path.parent if path.parent.exists() else Path(".")
        pattern = f"*{path.suffix}" if path.suffix else "*.py"

        stem_lower = path.stem.lower()
        for candidate in parent.glob(pattern):
            # Match if first 3 chars of stem match
            if len(stem_lower) >= 3 and candidate.stem.lower().startswith(
                stem_lower[:3]
            ):
                suggestions.append(str(candidate))
            # Or if candidate stem contains our stem
            elif stem_lower in candidate.stem.lower():
                suggestions.append(str(candidate))

        return suggestions[:3]  # Limit suggestions

    @staticmethod
    def generate_target_id(locator: str, name: str | None = None) -> str:
        """Generate stable target ID for persistence.

        Used by storage service to create consistent directory names
        in .serix/targets/<id>/.

        For Python targets, resolves relative paths to absolute paths
        before hashing. This ensures ./victim.py and ../project/victim.py
        point to the same target if they resolve to the same file.

        Args:
            locator: Target path or URL
            name: Optional user-provided name (takes precedence)

        Returns:
            Stable ID string (either name slug or hash of locator)
        """
        if name:
            # Slugify the name
            return name.lower().replace(" ", "-").replace("_", "-")

        # For Python targets, resolve to absolute path for stable hashing
        if not locator.startswith(("http://", "https://")):
            # Extract file path (before the : if present)
            file_path = locator.rsplit(":", 1)[0] if ":" in locator else locator
            resolved = Path(file_path).resolve()
            # Reconstruct with function name if present
            if ":" in locator:
                func_name = locator.rsplit(":", 1)[1]
                locator = f"{resolved}:{func_name}"
            else:
                locator = str(resolved)

        # Hash the locator for stable ID
        return hashlib.sha256(locator.encode()).hexdigest()[:12]
