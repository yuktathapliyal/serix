"""Abstract Target interface for Serix.

Target.send() is the universal interface for all attack modes:
- ScriptTarget: Monkey-patch approach for Python scripts
- DecoratorTarget: @serix.scan() decorator integration
- HttpTarget: HTTP endpoint testing for any language/framework
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx
from rich.console import Console

console = Console()


@dataclass
class TargetResponse:
    """Response from a target agent."""

    content: str
    raw_response: Any = None
    latency_ms: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class Target(ABC):
    """Abstract base class for all target types.

    The Target interface provides a unified way to send attack payloads
    to different types of AI agents (scripts, decorators, HTTP endpoints).
    """

    @abstractmethod
    def send(self, payload: str) -> TargetResponse:
        """Send an attack payload to the target and return the response.

        Args:
            payload: The attack string to send to the agent

        Returns:
            TargetResponse containing the agent's response
        """
        pass

    @abstractmethod
    def setup(self) -> None:
        """Prepare the target for receiving attacks."""
        pass

    @abstractmethod
    def teardown(self) -> None:
        """Clean up after attacks are complete."""
        pass


class ScriptTarget(Target):
    """Target that runs a Python script with monkey-patched OpenAI client.

    This preserves backwards compatibility with the existing attack mode.
    The script is executed with an injected user message containing the payload.
    """

    def __init__(
        self,
        script_path: Path,
        verbose: bool = False,
    ) -> None:
        self.script_path = script_path
        self.verbose = verbose
        self._original_openai: Any = None

    def setup(self) -> None:
        """Store original OpenAI class before patching."""
        import openai as openai_module

        self._original_openai = openai_module.OpenAI

    def teardown(self) -> None:
        """Restore original OpenAI class."""
        if self._original_openai:
            import openai as openai_module

            openai_module.OpenAI = self._original_openai  # type: ignore[misc]

    def send(self, payload: str) -> TargetResponse:
        """Execute script with attack payload injected as user message."""
        import time

        import openai as openai_module

        from serix.core.client import (
            SerixClient,
            get_original_openai_class,
            set_serix_config,
        )
        from serix.core.types import SerixConfig, SerixMode

        captured_responses: list[str] = []
        start_time = time.perf_counter()

        # Create attack client that injects payload
        class AttackClient(SerixClient):
            @property
            def chat(self) -> Any:
                class AttackChat:
                    @property
                    def completions(self) -> Any:
                        class AttackCompletions:
                            def create(
                                self_inner,
                                *,
                                model: str,
                                messages: list[dict],
                                **kwargs: Any,
                            ) -> Any:
                                # Inject attack payload as user message
                                modified_messages = messages.copy()
                                modified_messages.append(
                                    {"role": "user", "content": payload}
                                )

                                # Call original OpenAI
                                original = get_original_openai_class()
                                if original:
                                    client = original()
                                    response = client.chat.completions.create(
                                        model=model,
                                        messages=modified_messages,  # type: ignore[arg-type]
                                        **kwargs,
                                    )
                                    content = response.choices[0].message.content or ""
                                    captured_responses.append(content)
                                    return response
                                raise RuntimeError("No original client")

                        return AttackCompletions()

                return AttackChat()

        # Monkey patch and run
        openai_module.OpenAI = AttackClient  # type: ignore[misc]

        try:
            config = SerixConfig(mode=SerixMode.PASSTHROUGH, verbose=False)
            set_serix_config(config)

            # Add script directory to path
            script_dir = str(self.script_path.parent.resolve())
            if script_dir not in sys.path:
                sys.path.insert(0, script_dir)

            # Execute script
            script_code = self.script_path.read_text()
            script_globals = {
                "__name__": "__main__",
                "__file__": str(self.script_path.resolve()),
            }
            exec(compile(script_code, self.script_path, "exec"), script_globals)

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TargetResponse(
                content=f"[Script Error: {e}]",
                error=str(e),
                latency_ms=latency_ms,
            )
        finally:
            if self._original_openai:
                openai_module.OpenAI = self._original_openai  # type: ignore[misc]

        latency_ms = (time.perf_counter() - start_time) * 1000
        content = (
            "\n".join(captured_responses) if captured_responses else "[No response]"
        )

        return TargetResponse(
            content=content,
            latency_ms=latency_ms,
        )


class HttpTarget(Target):
    """Target that sends attacks to an HTTP endpoint.

    Supports any AI agent exposed via HTTP API, regardless of language/framework.
    """

    def __init__(
        self,
        url: str,
        method: str = "POST",
        input_field: str = "message",
        output_field: str = "response",
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        verbose: bool = False,
    ) -> None:
        self.url = url
        self.method = method.upper()
        self.input_field = input_field
        self.output_field = output_field
        self.headers = headers or {}
        self.timeout = timeout
        self.verbose = verbose
        self._client: httpx.Client | None = None

    def setup(self) -> None:
        """Initialize HTTP client."""
        self._client = httpx.Client(timeout=self.timeout)

    def verify_connectivity(self) -> None:
        """Check if HTTP target is reachable before attacking.

        Tries HEAD request first. Treats 405 as success (server is up).
        Only fails on actual connection errors.

        Raises:
            ConnectionError: If server is unreachable or times out.
        """
        if not self._client:
            self._client = httpx.Client(timeout=self.timeout)

        try:
            # HEAD is lightweight; any response means server is up
            self._client.head(self.url, timeout=5.0)
            return

        except httpx.HTTPStatusError as e:
            # 405 = server up but doesn't support HEAD, that's fine
            if e.response.status_code == 405:
                return
            # Other HTTP errors still mean server is reachable
            return

        except httpx.ConnectError as e:
            raise ConnectionError(
                f"Cannot connect to {self.url}\n"
                f"Connection refused - is the server running?"
            ) from e

        except httpx.ConnectTimeout as e:
            raise ConnectionError(
                f"Connection to {self.url} timed out\n"
                f"Server may be slow or unreachable."
            ) from e

        except httpx.TimeoutException as e:
            raise ConnectionError(f"Request to {self.url} timed out") from e

    def teardown(self) -> None:
        """Close HTTP client."""
        if self._client:
            self._client.close()
            self._client = None

    def send(self, payload: str) -> TargetResponse:
        """Send attack payload via HTTP and extract response."""
        import time

        if not self._client:
            self._client = httpx.Client(timeout=self.timeout)

        start_time = time.perf_counter()

        try:
            # Build request body
            body = {self.input_field: payload}

            if self.verbose:
                console.print(f"[dim]HTTP {self.method} {self.url}[/dim]")

            # Make request
            if self.method == "POST":
                response = self._client.post(
                    self.url,
                    json=body,
                    headers=self.headers,
                )
            elif self.method == "GET":
                response = self._client.get(
                    self.url,
                    params=body,
                    headers=self.headers,
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {self.method}")

            latency_ms = (time.perf_counter() - start_time) * 1000

            # Check for HTTP errors
            if response.status_code >= 400:
                return TargetResponse(
                    content=f"[HTTP Error {response.status_code}]",
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                    latency_ms=latency_ms,
                    raw_response=response,
                )

            # Parse JSON response
            try:
                data = response.json()
                # Extract content using output_field (supports nested paths like "data.message")
                content = data
                for key in self.output_field.split("."):
                    content = content.get(key, "") if isinstance(content, dict) else ""

                return TargetResponse(
                    content=str(content) if content else "[Empty response]",
                    raw_response=data,
                    latency_ms=latency_ms,
                )
            except Exception as e:
                return TargetResponse(
                    content=response.text[:500],
                    error=f"JSON parse error: {e}",
                    latency_ms=latency_ms,
                    raw_response=response,
                )

        except httpx.ConnectError as e:
            # Connection errors should fail loudly, not silently
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TargetResponse(
                content="",
                error=f"CONNECTION_REFUSED: {e}",
                latency_ms=latency_ms,
            )
        except httpx.TimeoutException:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TargetResponse(
                content="[Timeout]",
                error=f"Request timed out after {self.timeout}s",
                latency_ms=latency_ms,
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TargetResponse(
                content=f"[Error: {e}]",
                error=str(e),
                latency_ms=latency_ms,
            )


class DecoratorTarget(Target):
    """Target that wraps a decorated function.

    Used with @serix.scan() to test Python functions directly.
    """

    def __init__(
        self,
        func: Callable[[str], str],
        verbose: bool = False,
    ) -> None:
        self.func = func
        self.verbose = verbose

    def setup(self) -> None:
        """No setup needed for decorator target."""
        pass

    def teardown(self) -> None:
        """No teardown needed for decorator target."""
        pass

    def send(self, payload: str) -> TargetResponse:
        """Call the decorated function with the attack payload."""
        import time

        start_time = time.perf_counter()

        try:
            result = self.func(payload)
            latency_ms = (time.perf_counter() - start_time) * 1000

            return TargetResponse(
                content=str(result) if result else "[Empty response]",
                latency_ms=latency_ms,
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TargetResponse(
                content=f"[Error: {e}]",
                error=str(e),
                latency_ms=latency_ms,
            )
