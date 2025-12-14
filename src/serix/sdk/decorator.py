"""Serix decorator for clean Python agent integration.

This module provides the @serix.scan() decorator that marks functions
for security testing without requiring monkey-patching.

Usage:
    @serix.scan(scenarios=["injection", "pii_leak", "jailbreak"])
    def my_agent(user_input: str) -> str:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": user_input}
            ]
        )
        return response.choices[0].message.content
"""

from __future__ import annotations

import asyncio
import functools
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class ScanConfig:
    """Configuration for a scanned function."""

    scenarios: list[str] = field(default_factory=lambda: ["all"])
    dry_run: bool = True  # Intercept tool calls by default
    max_turns: int = 3  # Default for dev (prevent token burn)
    allow_list: list[str] = field(default_factory=list)  # Functions allowed in dry_run


@dataclass
class ScannedFunction:
    """Metadata for a function marked with @serix.scan()."""

    func: Callable[..., Any]
    config: ScanConfig
    name: str
    module: str
    is_async: bool


# Global registry of scanned functions
_scanned_functions: dict[str, ScannedFunction] = {}


def get_scanned_functions() -> dict[str, ScannedFunction]:
    """Get all functions registered with @serix.scan()."""
    return _scanned_functions.copy()


def get_scanned_function(name: str) -> ScannedFunction | None:
    """Get a specific scanned function by name."""
    return _scanned_functions.get(name)


class MockRegistry:
    """Intercepts function calls during scans to prevent dangerous operations.

    When dry_run=True (default), tool calls inside the agent are captured
    but not executed. This prevents accidentally deleting data or
    making real API calls during security testing.
    """

    def __init__(self, allow_list: list[str] | None = None) -> None:
        self.allow_list = allow_list or []
        self.intercepted_calls: list[dict[str, Any]] = []
        self._original_functions: dict[str, Callable[..., Any]] = {}

    def mock(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a function to intercept calls."""
        func_name = func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Allow listed functions execute normally
            if func_name in self.allow_list:
                return func(*args, **kwargs)

            # Intercept and record
            self.intercepted_calls.append(
                {
                    "function": func_name,
                    "args": args,
                    "kwargs": kwargs,
                }
            )
            return None  # Don't execute

        return wrapper

    def get_intercepted_calls(self) -> list[dict[str, Any]]:
        """Get list of intercepted function calls."""
        return self.intercepted_calls.copy()

    def clear(self) -> None:
        """Clear intercepted calls."""
        self.intercepted_calls.clear()


def scan(
    scenarios: list[str] | None = None,
    dry_run: bool = True,
    max_turns: int = 3,
    allow_list: list[str] | None = None,
) -> Callable[[F], F]:
    """Decorator to mark a function for Serix security scanning.

    Args:
        scenarios: List of attack scenarios to test (e.g., ["injection", "pii_leak"])
                   Default: ["all"] runs all scenarios
        dry_run: If True, intercept tool/function calls to prevent side effects
                 Default: True (safe mode)
        max_turns: Maximum attack turns for multi-turn attacks
                   Default: 3 (dev mode to prevent token burn)
        allow_list: Functions allowed to execute even in dry_run mode

    Returns:
        Decorated function with scan metadata attached

    Example:
        @serix.scan(scenarios=["injection", "jailbreak"], dry_run=True)
        def my_agent(user_input: str) -> str:
            return llm.generate(user_input)
    """

    def decorator(func: F) -> F:
        config = ScanConfig(
            scenarios=scenarios or ["all"],
            dry_run=dry_run,
            max_turns=max_turns,
            allow_list=allow_list or [],
        )

        # Determine function identity
        func_name = func.__name__
        module = func.__module__
        full_name = f"{module}.{func_name}" if module != "__main__" else func_name
        is_async = asyncio.iscoroutinefunction(func)

        # Register the scanned function
        scanned = ScannedFunction(
            func=func,
            config=config,
            name=func_name,
            module=module,
            is_async=is_async,
        )
        _scanned_functions[full_name] = scanned

        # Mark the function with metadata
        func._serix_config = config  # type: ignore[attr-defined]
        func._serix_scanned = True  # type: ignore[attr-defined]

        return func

    return decorator


class Agent:
    """Base class for more complex agents that need state management.

    For agents that maintain conversation history or have complex
    initialization, inherit from this class instead of using @scan.

    Example:
        class MyAgent(serix.Agent):
            def __init__(self):
                self.client = OpenAI()
                self.history = []

            def respond(self, user_input: str) -> str:
                self.history.append({"role": "user", "content": user_input})
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=self.history
                )
                content = response.choices[0].message.content
                self.history.append({"role": "assistant", "content": content})
                return content
    """

    _serix_scanned: bool = True
    _serix_config: ScanConfig | None = None

    def __init_subclass__(
        cls,
        scenarios: list[str] | None = None,
        dry_run: bool = True,
        max_turns: int = 3,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)
        cls._serix_config = ScanConfig(
            scenarios=scenarios or ["all"],
            dry_run=dry_run,
            max_turns=max_turns,
        )

    def respond(self, user_input: str) -> str:
        """Override this method to implement your agent's response logic.

        Args:
            user_input: The user's message (or attack payload during scanning)

        Returns:
            The agent's response string
        """
        raise NotImplementedError("Subclasses must implement respond()")

    def reset(self) -> None:
        """Reset agent state between attack attempts.

        Override this if your agent maintains conversation history
        that should be cleared between attacks.
        """
        pass


def load_function_from_path(path: str) -> Callable[..., Any]:
    """Load a function from a file path with function name.

    Args:
        path: Path in format "file.py:function_name"

    Returns:
        The loaded function

    Raises:
        ValueError: If path format is invalid
        ImportError: If function cannot be loaded
    """
    import importlib.util
    import sys
    from pathlib import Path

    if ":" not in path:
        raise ValueError(
            f"Invalid path format: {path}. " "Expected: path/to/file.py:function_name"
        )

    file_path, func_name = path.rsplit(":", 1)
    file_path_obj = Path(file_path)

    if not file_path_obj.exists():
        raise ImportError(f"File not found: {file_path}")

    # Add directory to path for imports
    file_dir = str(file_path_obj.parent.resolve())
    if file_dir not in sys.path:
        sys.path.insert(0, file_dir)

    # Load module
    module_name = file_path_obj.stem
    spec = importlib.util.spec_from_file_location(module_name, file_path_obj)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {file_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    # Get function
    if not hasattr(module, func_name):
        raise ImportError(
            f"Function '{func_name}' not found in {file_path}. "
            f"Available: {[n for n in dir(module) if not n.startswith('_')]}"
        )

    func = getattr(module, func_name)
    if not callable(func):
        raise ImportError(f"'{func_name}' is not callable")

    return func


def load_agent_from_path(path: str) -> Agent:
    """Load an Agent class from a file path.

    Args:
        path: Path in format "file.py:ClassName"

    Returns:
        Instantiated Agent

    Raises:
        ValueError: If path format is invalid or class is not an Agent
    """
    cls = load_function_from_path(path)

    if not (isinstance(cls, type) and issubclass(cls, Agent)):
        raise ValueError(f"'{path}' is not a serix.Agent subclass")

    return cls()
