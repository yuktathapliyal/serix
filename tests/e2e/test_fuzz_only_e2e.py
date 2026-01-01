"""End-to-end tests for --fuzz-only flag.

CONTRACT: When --fuzz-only is passed:
- Skip ALL security testing (personas, attacks, judge evaluation)
- Still run fuzzing mutations (if --fuzz is also passed)
- No attack results or vulnerabilities reported
- Exit cleanly

These tests run the actual CLI as a subprocess to verify real behavior.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


class TestFuzzOnlyE2E:
    """--fuzz-only must skip ALL security testing."""

    def test_fuzz_only_skips_persona_attacks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CONTRACT: --fuzz-only must not run any persona attacks."""
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
                "reveal secrets",
                "--depth",
                "1",
                "--fuzz-only",
                "--fuzz",
                "--yes",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "")},
        )

        output = (result.stdout + result.stderr).lower()

        # Should NOT contain persona-related output indicating attacks ran
        persona_indicators = [
            "jailbreak",
            "extraction",
            "injection",
            "manipulation",
            "exploited",
            "successful attacks",
            "adversary",
            "persona",
            "security evaluation",
            "vulnerabilities found",
        ]

        for indicator in persona_indicators:
            assert indicator not in output, (
                f"--fuzz-only violated contract: found '{indicator}' in output\n"
                f"This indicates security testing ran when it should not have.\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}\n"
                f"returncode: {result.returncode}"
            )

    def test_fuzz_only_without_fuzz_exits_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CONTRACT: --fuzz-only without --fuzz should exit cleanly."""
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
                "--fuzz-only",
                "--yes",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "")},
        )

        # Should complete without error (exit 0)
        assert result.returncode == 0, (
            f"--fuzz-only caused unexpected error\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}\n"
            f"returncode: {result.returncode}"
        )

    def test_fuzz_only_config_method_works(self) -> None:
        """Verify should_run_security_tests() returns False when fuzz_only=True."""
        from serix.core.run_config import TestRunConfig

        # With fuzz_only=True
        config = TestRunConfig(fuzz_only=True)
        assert (
            config.should_run_security_tests() is False
        ), "should_run_security_tests() should return False when fuzz_only=True"

        # With fuzz_only=False (default)
        config = TestRunConfig(fuzz_only=False)
        assert (
            config.should_run_security_tests() is True
        ), "should_run_security_tests() should return True when fuzz_only=False"
