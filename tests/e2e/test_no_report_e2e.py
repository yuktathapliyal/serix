"""End-to-end tests for --no-report flag.

CONTRACT: When --no-report is passed:
- NO HTML report generated (even if --report path is passed)
- .serix/ directory and attacks STILL saved (unlike --dry-run)

These tests run the actual CLI as a subprocess to verify real behavior.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


class TestNoReportE2E:
    """--no-report must skip report generation but NOT disk writes."""

    def test_no_report_creates_no_report_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CONTRACT: --no-report must not create report file even if --report is passed."""
        monkeypatch.chdir(tmp_path)

        report_path = tmp_path / "report.html"
        project_root = Path(__file__).parent.parent.parent

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "serix",
                "test",
                str(project_root / "examples" / "golden_victim.py") + ":golden_victim",
                "--goal",
                "test",
                "--depth",
                "1",
                "--report",
                str(report_path),
                "--no-report",
                "--yes",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "")},
        )

        assert not report_path.exists(), (
            f"--no-report violated contract: created report file\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}\n"
            f"returncode: {result.returncode}"
        )

    def test_no_report_does_not_imply_dry_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CONTRACT: --no-report must NOT set dry_run behavior.

        Unlike --dry-run, --no-report should still allow disk writes.
        We verify this by checking should_write_to_disk() returns True
        when --no-report is set but --dry-run is not.

        Note: We don't check .serix/ directory creation because that only
        happens when attacks are actually saved (requires winning_payload).
        """
        from serix.core.run_config import TestRunConfig

        # With --no-report but NOT --dry-run
        config = TestRunConfig(no_report=True, dry_run=False)

        # should_write_to_disk should still be True
        assert (
            config.should_write_to_disk() is True
        ), "--no-report incorrectly implies --dry-run behavior"

        # should_generate_report should be False (no report_path)
        assert config.should_generate_report() is False

    def test_no_report_without_report_flag_succeeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CONTRACT: --no-report without --report should complete successfully."""
        monkeypatch.chdir(tmp_path)

        project_root = Path(__file__).parent.parent.parent

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "serix",
                "test",
                str(project_root / "examples" / "golden_victim.py") + ":golden_victim",
                "--goal",
                "test",
                "--depth",
                "1",
                "--no-report",
                "--yes",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "")},
        )

        # Should complete without error (exit 0 or 1 for exploit found)
        assert result.returncode in (0, 1), (
            f"--no-report caused unexpected error\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}\n"
            f"returncode: {result.returncode}"
        )
