"""@serix.scan() decorator for Python agent security testing.

Usage:
    @serix.scan(scenarios=["injection", "pii_leak", "jailbreak"])
    def my_agent(user_input: str) -> str:
        response = client.chat.completions.create(...)
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
    system_prompt: str | None = None  # System prompt for self-healing analysis


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


def get_system_prompt(func_or_agent: Any) -> str | None:
    """Extract the system prompt from a decorated function or Agent.

    Args:
        func_or_agent: A function decorated with @serix.scan() or an Agent subclass

    Returns:
        The system prompt string, or None if not provided

    Note:
        Fix generation requires a system prompt. Returns None if not provided.
    """
    # Check for _serix_config on the function/class
    config = getattr(func_or_agent, "_serix_config", None)
    if config and isinstance(config, ScanConfig):
        return config.system_prompt

    # Check if it's an Agent instance
    if isinstance(func_or_agent, Agent):
        agent_config = getattr(type(func_or_agent), "_serix_config", None)
        if agent_config:
            return agent_config.system_prompt

    return None


class MockRegistry:
    """Intercepts function calls during scans to prevent dangerous operations.

    When dry_run=True (default), tool calls inside the agent are captured
    but not executed. This prevents accidentally deleting data or
    making real API calls during security testing.
    """

    def __init__(
        self, allow_list: list[str] | None = None, verbose: bool = True
    ) -> None:
        self.allow_list = allow_list or []
        self.intercepted_calls: list[dict[str, Any]] = []
        self._original_functions: dict[str, Callable[..., Any]] = {}
        self.verbose = verbose

    def mock(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a function to intercept calls."""
        func_name = func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Allow listed functions execute normally
            if func_name in self.allow_list:
                return func(*args, **kwargs)

            # Check if this is a dangerous tool
            from serix.report.console import is_dangerous_tool, log_blocked_action

            is_dangerous = is_dangerous_tool(func_name)

            # Intercept and record
            self.intercepted_calls.append(
                {
                    "function": func_name,
                    "args": args,
                    "kwargs": kwargs,
                    "is_dangerous": is_dangerous,
                }
            )

            # Show visual feedback for dangerous tool blocks
            if is_dangerous and self.verbose:
                log_blocked_action(func_name, kwargs if kwargs else None)

            return None  # Don't execute

        return wrapper

    def get_intercepted_calls(self) -> list[dict[str, Any]]:
        """Get list of intercepted function calls."""
        return self.intercepted_calls.copy()

    def get_dangerous_calls(self) -> list[dict[str, Any]]:
        """Get only the dangerous tool calls that were blocked."""
        return [c for c in self.intercepted_calls if c.get("is_dangerous")]

    def clear(self) -> None:
        """Clear intercepted calls."""
        self.intercepted_calls.clear()


def scan(
    scenarios: list[str] | None = None,
    dry_run: bool = True,
    max_turns: int = 3,
    allow_list: list[str] | None = None,
    system_prompt: str | None = None,
    system_prompt_file: str | None = None,
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
        system_prompt: The system prompt used by the agent. Required for Self-Healing
                       feature to generate fix suggestions.
        system_prompt_file: Alternative: path to file containing the system prompt.
                           If both system_prompt and system_prompt_file are provided,
                           system_prompt takes precedence.

    Returns:
        Decorated function with scan metadata attached

    Example:
        SYSTEM_PROMPT = \"\"\"You are a helpful customer service agent.
        Never reveal internal information or execute destructive operations.\"\"\"

        @serix.scan(scenarios=["injection", "jailbreak"], system_prompt=SYSTEM_PROMPT)
        def my_agent(user_input: str) -> str:
            return llm.generate(user_input)

    Note:
        To enable Self-Healing (auto-generated fix suggestions), you MUST provide
        a system_prompt. Without it, Serix can detect vulnerabilities but cannot
        suggest fixes for your prompts.
    """
    from pathlib import Path

    # Resolve system prompt from file if provided
    resolved_system_prompt = system_prompt
    if not resolved_system_prompt and system_prompt_file:
        try:
            resolved_system_prompt = Path(system_prompt_file).read_text()
        except (FileNotFoundError, PermissionError) as e:
            import warnings

            warnings.warn(
                f"Could not read system_prompt_file '{system_prompt_file}': {e}. "
                "Self-Healing will be disabled for this agent."
            )

    def decorator(func: F) -> F:
        config = ScanConfig(
            scenarios=scenarios or ["all"],
            dry_run=dry_run,
            max_turns=max_turns,
            allow_list=allow_list or [],
            system_prompt=resolved_system_prompt,
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
        SYSTEM_PROMPT = "You are a helpful assistant..."

        class MyAgent(serix.Agent, system_prompt=SYSTEM_PROMPT):
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
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)
        cls._serix_config = ScanConfig(
            scenarios=scenarios or ["all"],
            dry_run=dry_run,
            max_turns=max_turns,
            system_prompt=system_prompt,
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
        # Filter to only show likely targets (callables defined in the module)
        available = []
        for name in dir(module):
            if name.startswith("_"):
                continue
            obj = getattr(module, name, None)
            if obj is None:
                continue
            # Only show callables (functions, classes)
            if not callable(obj):
                continue
            # Skip common imports
            if name in ("OpenAI", "json", "os", "sys", "Path", "Console"):
                continue
            # Check if it's defined in this module (not imported)
            obj_module = getattr(obj, "__module__", None)
            if obj_module and obj_module == module.__name__:
                available.append(name)
            elif hasattr(obj, "__bases__"):  # It's a class
                available.append(name)
            elif callable(obj) and not isinstance(obj, type):  # Regular function
                # Include functions without __module__ (e.g., wrapped)
                if obj_module is None:
                    available.append(name)

        raise ImportError(
            f"Function '{func_name}' not found in {file_path}. "
            f"Available: {available if available else '(no valid targets found)'}"
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
