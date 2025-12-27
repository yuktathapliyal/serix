"""Tests for DevWorkflow."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from serix.core.types import SerixMode
from serix.workflows.dev_workflow import DevWorkflow, DevWorkflowResult


class TestDevWorkflowResult:
    """Tests for DevWorkflowResult."""

    def test_default_success(self) -> None:
        """Test successful result has exit code 0."""
        result = DevWorkflowResult(success=True, mode=SerixMode.PASSTHROUGH)
        assert result.exit_code == 0

    def test_failure_sets_exit_code(self) -> None:
        """Test failed result gets exit code 1."""
        result = DevWorkflowResult(success=False, mode=SerixMode.PASSTHROUGH)
        assert result.exit_code == 1

    def test_explicit_exit_code_preserved(self) -> None:
        """Test explicit exit code is preserved."""
        result = DevWorkflowResult(
            success=False, mode=SerixMode.PASSTHROUGH, exit_code=42
        )
        assert result.exit_code == 42


class TestDevWorkflowPassthrough:
    """Tests for passthrough mode."""

    def test_passthrough_success(self) -> None:
        """Test successful passthrough execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            script_path.write_text("x = 1 + 1")

            workflow = DevWorkflow()
            result = workflow.run_passthrough(script_path)

            assert result.success is True
            assert result.mode == SerixMode.PASSTHROUGH

    def test_passthrough_script_not_found(self) -> None:
        """Test passthrough with missing script."""
        workflow = DevWorkflow()
        result = workflow.run_passthrough(Path("/nonexistent/script.py"))

        assert result.success is False
        assert "not found" in result.error.lower()

    def test_passthrough_script_error(self) -> None:
        """Test passthrough with script that raises exception."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "error_script.py"
            script_path.write_text("raise ValueError('test error')")

            workflow = DevWorkflow()
            result = workflow.run_passthrough(script_path)

            assert result.success is False
            assert "test error" in result.error

    def test_passthrough_script_sys_exit(self) -> None:
        """Test passthrough with script that calls sys.exit()."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "exit_script.py"
            script_path.write_text("import sys; sys.exit(0)")

            workflow = DevWorkflow()
            result = workflow.run_passthrough(script_path)

            assert result.success is True
            assert result.exit_code == 0

    def test_passthrough_script_sys_exit_failure(self) -> None:
        """Test passthrough with script that exits with error code."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "exit_script.py"
            script_path.write_text("import sys; sys.exit(1)")

            workflow = DevWorkflow()
            result = workflow.run_passthrough(script_path)

            assert result.success is False
            assert result.exit_code == 1


class TestDevWorkflowCapture:
    """Tests for capture mode."""

    def test_capture_success(self) -> None:
        """Test successful capture execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            script_path.write_text("x = 1 + 1")

            workflow = DevWorkflow()
            result = workflow.run_capture(script_path)

            assert result.success is True
            assert result.mode == SerixMode.RECORD

    def test_capture_with_output_path(self) -> None:
        """Test capture saves to specified path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            script_path.write_text("x = 1 + 1")
            output_path = Path(tmpdir) / "recording.json"

            workflow = DevWorkflow()
            result = workflow.run_capture(script_path, output=output_path)

            assert result.success is True
            # No interactions, so recording_path is None
            assert result.recording_path is None
            assert result.interaction_count == 0

    def test_capture_script_not_found(self) -> None:
        """Test capture with missing script."""
        workflow = DevWorkflow()
        result = workflow.run_capture(Path("/nonexistent/script.py"))

        assert result.success is False
        assert result.mode == SerixMode.RECORD


class TestDevWorkflowPlayback:
    """Tests for playback mode."""

    def test_playback_file_not_found(self) -> None:
        """Test playback with missing recording."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            script_path.write_text("x = 1 + 1")

            workflow = DevWorkflow()
            result = workflow.run_playback(
                script_path, Path("/nonexistent/recording.json")
            )

            assert result.success is False
            assert "not found" in result.error.lower()

    def test_playback_success(self) -> None:
        """Test successful playback execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            script_path.write_text("x = 1 + 1")

            recording_path = Path(tmpdir) / "recording.json"
            recording_data = {
                "version": "1.0",
                "created_at": "2025-01-01T00:00:00",
                "script_path": str(script_path),
                "interactions": [],
            }
            with open(recording_path, "w") as f:
                json.dump(recording_data, f)

            workflow = DevWorkflow()
            result = workflow.run_playback(script_path, recording_path)

            assert result.success is True
            assert result.mode == SerixMode.REPLAY
            assert result.recording_path == recording_path


class TestDevWorkflowFuzz:
    """Tests for fuzz mode."""

    def test_fuzz_success(self) -> None:
        """Test successful fuzz execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            script_path.write_text("x = 1 + 1")

            workflow = DevWorkflow()
            result = workflow.run_fuzz(script_path, enable_latency=True)

            assert result.success is True
            assert result.mode == SerixMode.FUZZ

    def test_fuzz_all_mutations(self) -> None:
        """Test fuzz with all mutations enabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            script_path.write_text("x = 1 + 1")

            workflow = DevWorkflow()
            result = workflow.run_fuzz(
                script_path,
                enable_latency=True,
                enable_errors=True,
                enable_json_corruption=True,
            )

            assert result.success is True
            assert result.mode == SerixMode.FUZZ


class TestDevWorkflowScriptEnvironment:
    """Tests for script execution environment."""

    def test_script_has_correct_name(self) -> None:
        """Test script __name__ is set to __main__."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            output_file = Path(tmpdir) / "output.txt"
            script_path.write_text(
                f'with open("{output_file}", "w") as f: f.write(__name__)'
            )

            workflow = DevWorkflow()
            result = workflow.run_passthrough(script_path)

            assert result.success is True
            assert output_file.read_text() == "__main__"

    def test_script_has_correct_file(self) -> None:
        """Test script __file__ is set correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            output_file = Path(tmpdir) / "output.txt"
            script_path.write_text(
                f'with open("{output_file}", "w") as f: f.write(__file__)'
            )

            workflow = DevWorkflow()
            result = workflow.run_passthrough(script_path)

            assert result.success is True
            # __file__ should be the resolved path
            assert str(script_path.resolve()) in output_file.read_text()

    def test_script_can_import_from_same_directory(self) -> None:
        """Test script can import modules from its directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a helper module
            helper_path = Path(tmpdir) / "helper.py"
            helper_path.write_text("VALUE = 42")

            # Create main script that imports helper
            script_path = Path(tmpdir) / "main_script.py"
            output_file = Path(tmpdir) / "output.txt"
            script_path.write_text(
                f"""
import helper
with open("{output_file}", "w") as f:
    f.write(str(helper.VALUE))
"""
            )

            workflow = DevWorkflow()
            result = workflow.run_passthrough(script_path)

            assert result.success is True
            assert output_file.read_text() == "42"

    def test_sys_path_cleaned_up_after_execution(self) -> None:
        """Test script directory is removed from sys.path after execution."""
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "test_script.py"
            script_path.write_text("x = 1")

            script_dir = str(script_path.parent.resolve())
            initial_path_len = len(sys.path)

            workflow = DevWorkflow()
            result = workflow.run_passthrough(script_path)

            assert result.success is True
            # Path should be cleaned up
            assert script_dir not in sys.path
            # Path length should be same as before
            assert len(sys.path) == initial_path_len
