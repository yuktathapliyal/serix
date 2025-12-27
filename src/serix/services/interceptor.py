"""Interceptor service for OpenAI client patching.

Wraps the global state in core/client.py with a clean service interface
for capture, playback, and fuzz modes.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.client import (
    SerixClient,
    get_original_openai_class,
    get_recording_session,
    set_original_openai_class,
    set_recording_session,
    set_serix_config,
)
from ..core.constants import CAPTURES_DIR
from ..core.events import CaptureEvent, EventListener, NullEventListener, PlaybackEvent
from ..core.recorder import load_recording, save_recording
from ..core.types import FuzzConfig, RecordingSession, SerixConfig, SerixMode

if TYPE_CHECKING:
    pass


class InterceptorService:
    """Service for OpenAI client interception.

    Manages the lifecycle of:
    - Monkey-patching OpenAI client
    - Recording sessions (capture mode)
    - Playback sessions (playback mode)
    - Fuzzing configuration (fuzz mode)

    Wraps the global state in core/client.py with a cleaner interface.

    Example:
        interceptor = InterceptorService()
        interceptor.start_capture("my_script.py")
        interceptor.apply_patch()

        # ... run user script that uses openai.OpenAI() ...

        interceptor.remove_patch()
        path = interceptor.finalize_capture()
    """

    def __init__(
        self,
        event_listener: EventListener | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize interceptor service.

        Args:
            event_listener: Listener for capture/playback events
            verbose: Enable verbose logging
        """
        self._events: EventListener = event_listener or NullEventListener()
        self._verbose = verbose
        self._patched = False
        self._session: RecordingSession | None = None
        self._capture_path: Path | None = None
        self._mode: SerixMode = SerixMode.PASSTHROUGH

    @property
    def mode(self) -> SerixMode:
        """Get the current interception mode."""
        return self._mode

    @property
    def is_patched(self) -> bool:
        """Check if OpenAI client is currently patched."""
        return self._patched

    def configure(
        self,
        mode: SerixMode = SerixMode.PASSTHROUGH,
        fuzz_config: FuzzConfig | None = None,
        recording_file: str | None = None,
    ) -> None:
        """Configure the interceptor mode.

        Args:
            mode: Interception mode (passthrough, record, replay, fuzz)
            fuzz_config: Fuzzing configuration (for FUZZ mode)
            recording_file: Path to recording file (for REPLAY mode)
        """
        self._mode = mode
        config = SerixConfig(
            mode=mode,
            fuzz=fuzz_config or FuzzConfig(),
            verbose=self._verbose,
            recording_file=recording_file or "",
        )
        set_serix_config(config)

    def start_capture(
        self,
        script_path: str,
        output_path: Path | None = None,
    ) -> None:
        """Start a capture session.

        Records all OpenAI API calls made during script execution.

        Args:
            script_path: Path to the script being captured
            output_path: Where to save the recording (None = auto-generate)
        """
        self._session = RecordingSession(script_path=script_path)
        self._capture_path = output_path
        set_recording_session(self._session)
        self.configure(mode=SerixMode.RECORD)

    def start_playback(self, recording_path: Path) -> int:
        """Start a playback session.

        Replays recorded API responses instead of making network calls.

        Args:
            recording_path: Path to recording file

        Returns:
            Number of interactions in the recording

        Raises:
            FileNotFoundError: If recording doesn't exist
        """
        if not recording_path.exists():
            raise FileNotFoundError(f"Recording not found: {recording_path}")

        self._session = load_recording(recording_path)
        set_recording_session(self._session)
        self.configure(
            mode=SerixMode.REPLAY,
            recording_file=str(recording_path),
        )

        interaction_count = len(self._session.interactions)

        # Emit playback start event
        self._events.on_event(
            PlaybackEvent(
                index=0,
                model=(
                    self._session.interactions[0].request.model
                    if self._session.interactions
                    else "unknown"
                ),
            )
        )

        return interaction_count

    def start_fuzz(
        self,
        enable_latency: bool = False,
        enable_errors: bool = False,
        enable_json_corruption: bool = False,
    ) -> None:
        """Start fuzzing mode.

        Injects faults into API responses for resilience testing.

        Args:
            enable_latency: Inject random latency to API calls
            enable_errors: Inject HTTP errors (429, 500, 503)
            enable_json_corruption: Corrupt JSON responses
        """
        fuzz_config = FuzzConfig(
            enable_latency=enable_latency,
            enable_errors=enable_errors,
            enable_json_corruption=enable_json_corruption,
        )
        self.configure(mode=SerixMode.FUZZ, fuzz_config=fuzz_config)

    def apply_patch(self) -> None:
        """Apply monkey-patch to OpenAI client.

        After calling this, any `openai.OpenAI()` instantiation
        will use SerixClient instead.
        """
        import openai

        if not self._patched:
            # Store original for restoration
            set_original_openai_class(openai.OpenAI)
            openai.OpenAI = SerixClient  # type: ignore[misc]
            self._patched = True

    def remove_patch(self) -> None:
        """Remove monkey-patch, restoring original OpenAI client."""
        import openai

        original = get_original_openai_class()
        if original and self._patched:
            openai.OpenAI = original  # type: ignore[misc]
            self._patched = False

    def finalize_capture(self, output_path: Path | None = None) -> Path | None:
        """Finalize capture session and save recording.

        Args:
            output_path: Override output path (optional)

        Returns:
            Path to saved recording, or None if no interactions
        """
        session = get_recording_session()
        if not session or not session.interactions:
            return None

        # Determine output path
        path = output_path or self._capture_path
        if path is None:
            captures_dir = Path(CAPTURES_DIR)
            captures_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            script_name = Path(session.script_path or "recording").stem
            path = captures_dir / f"{script_name}_{timestamp}.json"

        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        save_recording(session, path)

        # Emit capture complete event
        self._events.on_event(
            CaptureEvent(
                index=len(session.interactions),
                model="capture",
                latency_ms=0,
            )
        )

        return path

    def get_interaction_count(self) -> int:
        """Get number of recorded/loaded interactions."""
        session = get_recording_session()
        return len(session.interactions) if session else 0

    def reset(self) -> None:
        """Reset interceptor to initial state.

        Removes patch and clears session state.
        """
        self.remove_patch()
        self._session = None
        self._capture_path = None
        self._mode = SerixMode.PASSTHROUGH
        set_recording_session(None)
