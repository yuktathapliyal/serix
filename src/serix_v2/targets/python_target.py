"""
Serix v2 - Python Function Target

Loads and calls Python functions/methods dynamically.

Law 3: Implements the Target protocol from core/protocols.py
Law 6: Uses generate_target_id() from core/id_gen.py for ID generation
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from serix.sdk.decorator import _scanned_functions, get_system_prompt
from serix_v2.core.id_gen import generate_target_id

if TYPE_CHECKING:
    from types import ModuleType


class PythonFunctionTarget:
    """Loads and calls a Python function or class method dynamically.

    Supports:
    - module.py:function_name
    - module.py:ClassName.method_name (zero-arg constructor)

    The Target protocol requires:
    - id: str property
    - locator: str property
    - __call__(message: str) -> str
    """

    def __init__(
        self,
        locator: str,
        name: str | None = None,  # --name flag (stable alias)
        explicit_id: str | None = None,  # --target-id flag (override)
    ) -> None:
        """Initialize the Python function target.

        Args:
            locator: Path to the function in format "module.py:function_name"
                     or "module.py:ClassName.method_name"
            name: Optional stable alias for ID generation (--name flag)
            explicit_id: Optional explicit ID override (--target-id flag)
        """
        self._locator = locator
        # Law 6: Generate ID using core logic with full precedence
        # explicit_id > name > auto-hash from locator
        self._id = generate_target_id(
            locator=locator,
            name=name,
            explicit_id=explicit_id,
        )
        self._func = self._load_callable(locator)

    def _load_callable(self, locator: str) -> Callable[[str], str]:
        """Load a callable from a locator string.

        Args:
            locator: Path in format "path/to/module.py:target" where target
                     is either a function name or "ClassName.method_name"

        Returns:
            A callable that takes a string and returns a string.

        Raises:
            FileNotFoundError: If the module file doesn't exist
            AttributeError: If the function/class/method doesn't exist
            ValueError: If the locator format is invalid
        """
        if ":" not in locator:
            raise ValueError(
                f"Invalid locator format: '{locator}'. "
                "Expected 'path/to/module.py:function_name' or "
                "'path/to/module.py:ClassName.method_name'"
            )

        file_path, target = locator.rsplit(":", 1)

        # CRITICAL: Always resolve() to absolute path first
        # This prevents crashes when running from different directories
        abs_path = Path(file_path).resolve()

        if not abs_path.exists():
            raise FileNotFoundError(f"Module file not found: '{abs_path}'")

        # Ensure local imports within the target script work
        parent_dir = str(abs_path.parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)

        # Load module with importlib.util
        module = self._load_module(abs_path)

        if "." in target:
            # Class.method syntax - zero-arg constructor
            class_name, method_name = target.split(".", 1)
            try:
                cls = getattr(module, class_name)
            except AttributeError:
                available = [n for n in dir(module) if not n.startswith("_")]
                raise AttributeError(
                    f"Class '{class_name}' not found in module. "
                    f"Available: {available}"
                )
            instance = cls()
            try:
                method = getattr(instance, method_name)
            except AttributeError:
                available = [n for n in dir(instance) if not n.startswith("_")]
                raise AttributeError(
                    f"Method '{method_name}' not found on class '{class_name}'. "
                    f"Available: {available}"
                )
            return method
        else:
            # Plain function
            try:
                func = getattr(module, target)
            except AttributeError:
                available = [n for n in dir(module) if not n.startswith("_")]
                raise AttributeError(
                    f"Function '{target}' not found in module. "
                    f"Available: {available}"
                )
            if not callable(func):
                raise TypeError(f"'{target}' is not callable")
            return func

    def _load_module(self, abs_path: Path) -> "ModuleType":
        """Load a Python module from an absolute path.

        Args:
            abs_path: Absolute path to the Python module file.

        Returns:
            The loaded module.
        """
        module_name = f"serix_target_{abs_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, str(abs_path))
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from: '{abs_path}'")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    @property
    def id(self) -> str:
        """Unique identifier for this target."""
        return self._id

    @property
    def locator(self) -> str:
        """Original locator string."""
        return self._locator

    @property
    def system_prompt(self) -> str | None:
        """Extract system prompt from @serix.scan() decorator if present.

        Returns:
            The system_prompt string from the decorator, or None if not found.
        """
        return self._extract_system_prompt()

    def _extract_system_prompt(self) -> str | None:
        """Look up system prompt from the scanned functions registry.

        Checks both the direct function and registry lookups.

        Returns:
            The system_prompt string if found, None otherwise.
        """
        # First try direct extraction from the function (handles Agent subclasses too)
        prompt = get_system_prompt(self._func)
        if prompt:
            return prompt

        # For bound methods (Class.method), check the instance itself
        # This handles serix.Agent subclasses where config is on the class
        if hasattr(self._func, "__self__"):
            instance = self._func.__self__
            prompt = get_system_prompt(instance)
            if prompt:
                return prompt

        # Check the global registry for full module.function names
        for key, scanned in _scanned_functions.items():
            if scanned.func is self._func:
                return scanned.config.system_prompt

        return None

    def __call__(self, message: str) -> str:
        """Send a message to the target and get a response.

        Args:
            message: The attack payload to send.

        Returns:
            The target's response as a string.
        """
        result = self._func(message)
        # Ensure we always return a string
        if result is None:
            return ""
        return str(result)

    def __repr__(self) -> str:
        return f"PythonFunctionTarget(locator={self._locator!r}, id={self._id!r})"
