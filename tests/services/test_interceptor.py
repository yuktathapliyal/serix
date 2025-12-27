"""Tests for InterceptorService."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from serix.core.events import CaptureEvent, PlaybackEvent
from serix.core.types import FuzzConfig, SerixMode
from serix.services.interceptor import InterceptorService


class TestInterceptorServiceInit:
    """Tests for InterceptorService initialization."""

    def test_default_initialization(self) -> None:
        """Test default initialization values."""
        service = InterceptorService()

        assert service.mode == SerixMode.PASSTHROUGH
        assert service.is_patched is False

    def test_verbose_initialization(self) -> None:
        """Test verbose flag is stored."""
        service = InterceptorService(verbose=True)

        assert service._verbose is True

    def test_event_listener_initialization(self) -> None:
        """Test custom event listener is stored."""
        listener = MagicMock()
        service = InterceptorService(event_listener=listener)

        assert service._events is listener


class TestInterceptorServiceConfigure:
    """Tests for configure() method."""

    def test_configure_passthrough_mode(self) -> None:
        """Test configuring passthrough mode."""
        service = InterceptorService()
        service.configure(mode=SerixMode.PASSTHROUGH)

        assert service.mode == SerixMode.PASSTHROUGH

    def test_configure_record_mode(self) -> None:
        """Test configuring record mode."""
        service = InterceptorService()
        service.configure(mode=SerixMode.RECORD)

        assert service.mode == SerixMode.RECORD

    def test_configure_replay_mode(self) -> None:
        """Test configuring replay mode with recording file."""
        service = InterceptorService()
        service.configure(
            mode=SerixMode.REPLAY,
            recording_file="/path/to/recording.json",
        )

        assert service.mode == SerixMode.REPLAY

    def test_configure_fuzz_mode(self) -> None:
        """Test configuring fuzz mode with config."""
        service = InterceptorService()
        fuzz_config = FuzzConfig(
            enable_latency=True,
            enable_errors=False,
            enable_json_corruption=True,
        )
        service.configure(mode=SerixMode.FUZZ, fuzz_config=fuzz_config)

        assert service.mode == SerixMode.FUZZ


class TestInterceptorServicePatch:
    """Tests for apply_patch() and remove_patch() methods."""

    def test_apply_patch(self) -> None:
        """Test applying monkey-patch to OpenAI."""
        import openai

        from serix.core.client import SerixClient

        service = InterceptorService()
        original_class = openai.OpenAI

        try:
            service.apply_patch()

            assert service.is_patched is True
            assert openai.OpenAI is SerixClient
        finally:
            # Clean up
            openai.OpenAI = original_class

    def test_remove_patch(self) -> None:
        """Test removing monkey-patch restores original."""
        import openai

        service = InterceptorService()
        original_class = openai.OpenAI

        try:
            service.apply_patch()
            assert service.is_patched is True

            service.remove_patch()
            assert service.is_patched is False
            assert openai.OpenAI is original_class
        finally:
            # Ensure cleanup
            openai.OpenAI = original_class

    def test_apply_patch_idempotent(self) -> None:
        """Test applying patch twice doesn't break anything."""
        import openai

        service = InterceptorService()
        original_class = openai.OpenAI

        try:
            service.apply_patch()
            service.apply_patch()  # Second call should be no-op

            assert service.is_patched is True
        finally:
            openai.OpenAI = original_class

    def test_remove_patch_without_apply(self) -> None:
        """Test removing patch when not applied is safe."""
        service = InterceptorService()

        # Should not raise
        service.remove_patch()
        assert service.is_patched is False


class TestInterceptorServiceCapture:
    """Tests for capture mode functionality."""

    def test_start_capture(self) -> None:
        """Test starting a capture session."""
        service = InterceptorService()
        service.start_capture("test_script.py")

        assert service.mode == SerixMode.RECORD
        assert service.get_interaction_count() == 0

    def test_start_capture_with_output_path(self) -> None:
        """Test starting capture with custom output path."""
        service = InterceptorService()
        output_path = Path("/tmp/my_recording.json")
        service.start_capture("test_script.py", output_path=output_path)

        assert service._capture_path == output_path

    def test_finalize_capture_no_interactions(self) -> None:
        """Test finalizing capture with no interactions returns None."""
        service = InterceptorService()
        service.start_capture("test_script.py")

        result = service.finalize_capture()

        assert result is None

    def test_finalize_capture_with_interactions(self) -> None:
        """Test finalizing capture saves to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "recording.json"

            service = InterceptorService()
            service.start_capture("test_script.py", output_path=output_path)

            # Manually add an interaction to the session
            from serix.core.client import get_recording_session
            from serix.core.types import RecordedRequest, RecordedResponse

            session = get_recording_session()
            assert session is not None

            request = RecordedRequest(
                model="gpt-4",
                messages=[{"role": "user", "content": "test"}],
            )
            response = RecordedResponse(
                id="test-id",
                model="gpt-4",
                choices=[{"message": {"content": "response"}}],
                created=1234567890,
            )
            session.add_interaction(request, response, latency_ms=100.0)

            result = service.finalize_capture()

            assert result == output_path
            assert output_path.exists()

            # Verify JSON content
            with open(output_path) as f:
                data = json.load(f)
            assert len(data["interactions"]) == 1

    def test_finalize_capture_emits_event(self) -> None:
        """Test finalizing capture emits CaptureEvent."""
        listener = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "recording.json"

            service = InterceptorService(event_listener=listener)
            service.start_capture("test_script.py", output_path=output_path)

            # Add an interaction
            from serix.core.client import get_recording_session
            from serix.core.types import RecordedRequest, RecordedResponse

            session = get_recording_session()
            request = RecordedRequest(model="gpt-4", messages=[])
            response = RecordedResponse(id="test", model="gpt-4", choices=[], created=0)
            session.add_interaction(request, response, 0)

            service.finalize_capture()

            # Check event was emitted
            assert listener.on_event.called
            event = listener.on_event.call_args[0][0]
            assert isinstance(event, CaptureEvent)


class TestInterceptorServicePlayback:
    """Tests for playback mode functionality."""

    def test_start_playback_file_not_found(self) -> None:
        """Test starting playback with missing file raises."""
        service = InterceptorService()

        with pytest.raises(FileNotFoundError):
            service.start_playback(Path("/nonexistent/recording.json"))

    def test_start_playback_success(self) -> None:
        """Test starting playback loads recording."""
        with tempfile.TemporaryDirectory() as tmpdir:
            recording_path = Path(tmpdir) / "recording.json"

            # Create a recording file
            recording_data = {
                "version": "1.0",
                "created_at": "2025-01-01T00:00:00",
                "script_path": "test.py",
                "interactions": [
                    {
                        "index": 0,
                        "request": {
                            "model": "gpt-4",
                            "messages": [],
                            "timestamp": "2025-01-01T00:00:00",
                        },
                        "response": {
                            "id": "test",
                            "model": "gpt-4",
                            "choices": [],
                            "created": 0,
                        },
                        "latency_ms": 100,
                    }
                ],
            }
            with open(recording_path, "w") as f:
                json.dump(recording_data, f)

            service = InterceptorService()
            count = service.start_playback(recording_path)

            assert count == 1
            assert service.mode == SerixMode.REPLAY

    def test_start_playback_emits_event(self) -> None:
        """Test starting playback emits PlaybackEvent."""
        listener = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            recording_path = Path(tmpdir) / "recording.json"

            recording_data = {
                "version": "1.0",
                "created_at": "2025-01-01T00:00:00",
                "script_path": "test.py",
                "interactions": [
                    {
                        "index": 0,
                        "request": {
                            "model": "gpt-4",
                            "messages": [],
                            "timestamp": "2025-01-01T00:00:00",
                        },
                        "response": {
                            "id": "test",
                            "model": "gpt-4",
                            "choices": [],
                            "created": 0,
                        },
                        "latency_ms": 100,
                    }
                ],
            }
            with open(recording_path, "w") as f:
                json.dump(recording_data, f)

            service = InterceptorService(event_listener=listener)
            service.start_playback(recording_path)

            assert listener.on_event.called
            event = listener.on_event.call_args[0][0]
            assert isinstance(event, PlaybackEvent)


class TestInterceptorServiceFuzz:
    """Tests for fuzz mode functionality."""

    def test_start_fuzz_all(self) -> None:
        """Test starting fuzz mode with all mutations."""
        service = InterceptorService()
        service.start_fuzz(
            enable_latency=True,
            enable_errors=True,
            enable_json_corruption=True,
        )

        assert service.mode == SerixMode.FUZZ

    def test_start_fuzz_latency_only(self) -> None:
        """Test starting fuzz mode with latency only."""
        service = InterceptorService()
        service.start_fuzz(enable_latency=True)

        assert service.mode == SerixMode.FUZZ

    def test_start_fuzz_errors_only(self) -> None:
        """Test starting fuzz mode with errors only."""
        service = InterceptorService()
        service.start_fuzz(enable_errors=True)

        assert service.mode == SerixMode.FUZZ


class TestInterceptorServiceReset:
    """Tests for reset() method."""

    def test_reset_clears_state(self) -> None:
        """Test reset clears all state."""
        service = InterceptorService()
        service.start_capture("test.py")

        assert service.mode == SerixMode.RECORD

        service.reset()

        assert service.mode == SerixMode.PASSTHROUGH
        assert service._session is None
        assert service._capture_path is None

    def test_reset_removes_patch(self) -> None:
        """Test reset removes monkey-patch."""
        import openai

        service = InterceptorService()
        original_class = openai.OpenAI

        try:
            service.apply_patch()
            assert service.is_patched is True

            service.reset()
            assert service.is_patched is False
        finally:
            openai.OpenAI = original_class
