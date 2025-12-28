"""Behavioral contract tests for TestWorkflow flag handling.

These tests verify that TestWorkflow respects configuration flags
by calling or skipping methods appropriately.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from serix.core.run_config import TestRunConfig
from serix.workflows.test_workflow import TestWorkflow

if TYPE_CHECKING:
    pass


class TestWorkflowDryRun:
    """--dry-run must prevent storage creation."""

    def test_dry_run_no_storage_created(self) -> None:
        """With dry_run=True, _storage must be None."""
        config = TestRunConfig(dry_run=True)
        workflow = TestWorkflow(config)
        assert workflow._storage is None

    def test_no_dry_run_storage_created(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without dry_run, storage is created."""
        monkeypatch.chdir(tmp_path)
        config = TestRunConfig(dry_run=False)
        workflow = TestWorkflow(config)
        assert workflow._storage is not None


class TestWorkflowFuzzOnly:
    """--fuzz-only must skip security tests."""

    def test_fuzz_only_skips_security_tests(self, mock_target: MagicMock) -> None:
        """With fuzz_only=True, _run_security_tests not called."""
        config = TestRunConfig(fuzz_only=True, fuzz_enabled=True, dry_run=True)
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_run_security_tests") as mock_security:
            with patch.object(workflow, "_run_fuzzing") as mock_fuzz:
                workflow.run(mock_target)
                mock_security.assert_not_called()
                mock_fuzz.assert_called_once()

    def test_without_fuzz_only_runs_security_tests(
        self, mock_target: MagicMock
    ) -> None:
        """Without fuzz_only, _run_security_tests is called."""
        config = TestRunConfig(fuzz_only=False, dry_run=True)
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_run_security_tests") as mock_security:
            workflow.run(mock_target)
            mock_security.assert_called_once()


class TestWorkflowSkipRegression:
    """--skip-regression must skip immune check."""

    def test_skip_regression_skips_regression_check(
        self, mock_target: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With skip_regression=True, _run_regression_check not called."""
        monkeypatch.chdir(tmp_path)
        config = TestRunConfig(skip_regression=True)
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_run_regression_check") as mock_regression:
            workflow.run(mock_target)
            mock_regression.assert_not_called()

    def test_without_skip_regression_runs_regression_check(
        self, mock_target: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without skip_regression, _run_regression_check is called (when storage exists)."""
        monkeypatch.chdir(tmp_path)
        config = TestRunConfig(skip_regression=False)
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_run_regression_check") as mock_regression:
            workflow.run(mock_target)
            # Called because storage exists (dry_run=False)
            mock_regression.assert_called_once()


class TestWorkflowNoReport:
    """--no-report must skip report generation."""

    def test_no_report_skips_report_generation(self, mock_target: MagicMock) -> None:
        """With no_report=True, _generate_report not called."""
        config = TestRunConfig(
            no_report=True, report_path=Path("report.html"), dry_run=True
        )
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_generate_report") as mock_report:
            # Need to mock security tests to return results
            with patch.object(
                workflow, "_run_security_tests", return_value={"some": "results"}
            ):
                workflow.run(mock_target)
                mock_report.assert_not_called()

    def test_without_no_report_generates_report(self, mock_target: MagicMock) -> None:
        """Without no_report and with path, _generate_report is called."""
        config = TestRunConfig(
            no_report=False, report_path=Path("report.html"), dry_run=True
        )
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_generate_report") as mock_report:
            # Need to mock security tests to return results
            with patch.object(
                workflow, "_run_security_tests", return_value={"some": "results"}
            ):
                workflow.run(mock_target)
                mock_report.assert_called_once()


class TestWorkflowNoPatch:
    """--no-patch must skip patch generation."""

    def test_no_patch_skips_patch_generation(self, mock_target: MagicMock) -> None:
        """With no_patch=True, _generate_patches not called."""
        config = TestRunConfig(no_patch=True, dry_run=True)
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_generate_patches") as mock_patches:
            # Need to mock security tests to return results
            with patch.object(
                workflow, "_run_security_tests", return_value={"some": "results"}
            ):
                workflow.run(mock_target)
                mock_patches.assert_not_called()

    def test_without_no_patch_generates_patches(self, mock_target: MagicMock) -> None:
        """Without no_patch, _generate_patches is called."""
        config = TestRunConfig(no_patch=False, dry_run=True)
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_generate_patches") as mock_patches:
            # Need to mock security tests to return results
            with patch.object(
                workflow, "_run_security_tests", return_value={"some": "results"}
            ):
                workflow.run(mock_target)
                mock_patches.assert_called_once()


class TestWorkflowFuzzEnabled:
    """--fuzz must enable fuzzing."""

    def test_fuzz_enabled_runs_fuzzing(self, mock_target: MagicMock) -> None:
        """With fuzz_enabled=True, _run_fuzzing is called."""
        config = TestRunConfig(fuzz_enabled=True, dry_run=True)
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_run_fuzzing") as mock_fuzz:
            workflow.run(mock_target)
            mock_fuzz.assert_called_once()

    def test_fuzz_disabled_skips_fuzzing(self, mock_target: MagicMock) -> None:
        """Without fuzz_enabled, _run_fuzzing is not called."""
        config = TestRunConfig(fuzz_enabled=False, dry_run=True)
        workflow = TestWorkflow(config)

        with patch.object(workflow, "_run_fuzzing") as mock_fuzz:
            workflow.run(mock_target)
            mock_fuzz.assert_not_called()
