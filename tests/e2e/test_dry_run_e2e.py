"""End-to-end tests for --dry-run flag.

CONTRACT: When --dry-run is passed, NO files shall be written to disk.
This includes:
- .serix/ directory and contents
- Report files (HTML, JSON)
- Any other file artifacts

These tests run the actual CLI as a subprocess to verify real behavior.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


class TestDryRunE2E:
    """--dry-run must not write ANY files to disk."""

    def test_dry_run_creates_no_serix_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CONTRACT: --dry-run must not create .serix/ directory."""
        monkeypatch.chdir(tmp_path)

        # Ensure no .serix exists before
        serix_dir = tmp_path / ".serix"
        assert not serix_dir.exists(), "Precondition failed: .serix already exists"

        # Get the project root for examples path
        project_root = Path(__file__).parent.parent.parent

        # Run with --dry-run
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
                "--dry-run",
                "--yes",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "")},
        )

        # Assert: .serix/ must NOT be created
        assert not serix_dir.exists(), (
            f"--dry-run violated contract: created .serix/ directory\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}\n"
            f"returncode: {result.returncode}"
        )

    def test_dry_run_creates_no_report_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CONTRACT: --dry-run must not create report file even if --report is passed."""
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
                "--dry-run",
                "--report",
                str(report_path),
                "--yes",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "")},
        )

        assert not report_path.exists(), (
            f"--dry-run violated contract: created report file\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
