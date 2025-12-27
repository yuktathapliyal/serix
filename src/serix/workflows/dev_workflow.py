"""Dev workflow for running scripts with OpenAI interception.

Orchestrates running user scripts with capture, playback, or fuzz modes.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.events import EventListener, NullEventListener
from ..core.types import SerixMode
from ..services.interceptor import InterceptorService

if TYPE_CHECKING:
    pass


@dataclass
class DevWorkflowResult:
    """Result from dev workflow execution."""

    success: bool
    mode: SerixMode
    recording_path: Path | None = None
    interaction_count: int = 0
    error: str | None = None
    exit_code: int = 0

    def __post_init__(self) -> None:
        """Set exit code based on success."""
        if not self.success and self.exit_code == 0:
            self.exit_code = 1


class DevWorkflow:
    """Workflow for running scripts with OpenAI interception.

    Supports modes:
    - Passthrough: Run script normally, intercept for logging only
    - Capture: Record all API interactions to JSON
    - Playback: Replay from recorded interactions (no API calls)
    - Fuzz: Inject faults (latency, errors, JSON corruption)

    Example:
        workflow = DevWorkflow()
        result = workflow.run_capture(Path("my_agent.py"))
        if result.success:
            print(f"Recorded to {result.recording_path}")
    """

    def __init__(
        self,
        interceptor: InterceptorService | None = None,
        event_listener: EventListener | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize dev workflow.

        Args:
            interceptor: Interceptor service (created if not provided)
            event_listener: Listener for workflow events
            verbose: Enable verbose output
        """
        self._events: EventListener = event_listener or NullEventListener()
        self._verbose = verbose
        self._interceptor = interceptor or InterceptorService(
            event_listener=event_listener,
            verbose=verbose,
        )

    def run_passthrough(self, script: Path) -> DevWorkflowResult:
        """Run script in passthrough mode (normal execution with interception).

        Args:
            script: Path to Python script

        Returns:
            DevWorkflowResult with execution status
        """
        self._interceptor.configure(mode=SerixMode.PASSTHROUGH)
        return self._execute_script(script, SerixMode.PASSTHROUGH)

    def run_capture(
        self,
        script: Path,
        output: Path | None = None,
    ) -> DevWorkflowResult:
        """Run script and capture all API interactions.

        Args:
            script: Path to Python script
            output: Custom output path for recording (auto-generated if None)

        Returns:
            DevWorkflowResult with recording path if successful
        """
        self._interceptor.start_capture(str(script), output)
        result = self._execute_script(script, SerixMode.RECORD)

        # Finalize and save recording
        if result.success:
            result.recording_path = self._interceptor.finalize_capture(output)
            result.interaction_count = self._interceptor.get_interaction_count()

        return result

    def run_playback(self, script: Path, recording: Path) -> DevWorkflowResult:
        """Run script using recorded API responses (no network calls).

        Args:
            script: Path to Python script
            recording: Path to recording file

        Returns:
            DevWorkflowResult with playback status
        """
        try:
            interaction_count = self._interceptor.start_playback(recording)
        except FileNotFoundError as e:
            return DevWorkflowResult(
                success=False,
                mode=SerixMode.REPLAY,
                error=str(e),
            )

        result = self._execute_script(script, SerixMode.REPLAY)
        result.interaction_count = interaction_count
        result.recording_path = recording
        return result

    def run_fuzz(
        self,
        script: Path,
        enable_latency: bool = False,
        enable_errors: bool = False,
        enable_json_corruption: bool = False,
    ) -> DevWorkflowResult:
        """Run script with fault injection.

        Args:
            script: Path to Python script
            enable_latency: Inject random latency
            enable_errors: Inject HTTP errors
            enable_json_corruption: Corrupt JSON responses

        Returns:
            DevWorkflowResult with fuzz execution status
        """
        self._interceptor.start_fuzz(
            enable_latency=enable_latency,
            enable_errors=enable_errors,
            enable_json_corruption=enable_json_corruption,
        )
        return self._execute_script(script, SerixMode.FUZZ)

    def _execute_script(self, script: Path, mode: SerixMode) -> DevWorkflowResult:
        """Execute a Python script with interception enabled.

        Args:
            script: Path to Python script
            mode: Current interception mode

        Returns:
            DevWorkflowResult with execution status
        """
        if not script.exists():
            return DevWorkflowResult(
                success=False,
                mode=mode,
                error=f"Script not found: {script}",
            )

        # Apply monkey patch
        self._interceptor.apply_patch()

        # Add script directory to path for imports
        script_dir = str(script.parent.resolve())
        path_added = False
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
            path_added = True

        # Visual separator to distinguish script output from Serix output
        if self._verbose:
            from rich.console import Console

            Console().print("\n[dim]─── Script Output ───[/dim]")

        try:
            # Read and execute script
            script_code = script.read_text()
            script_globals: dict[str, Any] = {
                "__name__": "__main__",
                "__file__": str(script.resolve()),
            }
            exec(compile(script_code, script, "exec"), script_globals)

            return DevWorkflowResult(success=True, mode=mode)

        except SystemExit as e:
            # Handle sys.exit() calls from script
            exit_code = e.code if isinstance(e.code, int) else 0
            return DevWorkflowResult(
                success=exit_code == 0,
                mode=mode,
                exit_code=exit_code,
            )

        except Exception as e:
            return DevWorkflowResult(
                success=False,
                mode=mode,
                error=str(e),
            )

        finally:
            # Visual separator after script output
            if self._verbose:
                from rich.console import Console

                Console().print("[dim]─── End Script ───[/dim]\n")

            # Clean up: restore original OpenAI class
            self._interceptor.remove_patch()

            # Clean up: remove script dir from path if we added it
            if path_added and script_dir in sys.path:
                sys.path.remove(script_dir)
