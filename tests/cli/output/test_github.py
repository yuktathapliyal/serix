"""Tests for GithubRenderer."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from serix.cli.output.github import GithubRenderer, is_github_actions
from serix.core.events import (
    AttackCompletedEvent,
    RegressionCompletedEvent,
    RegressionStartedEvent,
    WorkflowCompletedEvent,
    WorkflowStartedEvent,
)


class TestGithubRendererBasic:
    """Tests for basic GithubRenderer functionality."""

    def test_init(self) -> None:
        """Test initialization."""
        renderer = GithubRenderer()
        assert renderer._exploits == []
        assert renderer._regression_still_exploited == 0
        assert renderer._regression_now_defended == 0

    def test_stores_target_on_workflow_start(self) -> None:
        """Test that target is stored on workflow start."""
        renderer = GithubRenderer()
        renderer.on_event(
            WorkflowStartedEvent(
                command="test",
                target="my_agent.py:agent",
                goals=["reveal secrets"],
            )
        )
        assert renderer._target == "my_agent.py:agent"


class TestGithubRendererAttackEvents:
    """Tests for attack event handling."""

    def test_emits_error_on_successful_exploit(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Test that ::error:: is emitted for successful exploits."""
        renderer = GithubRenderer()
        renderer.on_event(
            AttackCompletedEvent(
                persona="jailbreaker",
                goal="reveal secrets",
                success=True,
                confidence=0.9,
                owasp_code="LLM01",
                turns_taken=3,
            )
        )

        captured = capsys.readouterr()
        assert "::error" in captured.out
        assert "LLM01" in captured.out
        assert "jailbreaker" in captured.out

    def test_no_error_on_defended_attack(self, capsys: pytest.CaptureFixture) -> None:
        """Test that no ::error:: is emitted for defended attacks."""
        renderer = GithubRenderer()
        renderer.on_event(
            AttackCompletedEvent(
                persona="jailbreaker",
                goal="reveal secrets",
                success=False,
                confidence=0.0,
                owasp_code=None,
                turns_taken=5,
            )
        )

        captured = capsys.readouterr()
        assert "::error" not in captured.out

    def test_tracks_exploits(self) -> None:
        """Test that exploits are tracked for summary."""
        renderer = GithubRenderer()
        renderer.on_event(
            AttackCompletedEvent(
                persona="jailbreaker",
                goal="reveal secrets",
                success=True,
                confidence=0.9,
                owasp_code="LLM01",
                turns_taken=3,
            )
        )

        assert len(renderer._exploits) == 1
        assert renderer._exploits[0]["persona"] == "jailbreaker"
        assert renderer._exploits[0]["owasp_code"] == "LLM01"


class TestGithubRendererRegressionEvents:
    """Tests for regression event handling."""

    def test_emits_warning_on_still_exploited(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Test that ::warning:: is emitted when exploits still work."""
        renderer = GithubRenderer()
        renderer.on_event(RegressionStartedEvent(total_attacks=2))
        renderer.on_event(
            RegressionCompletedEvent(
                total_replayed=2,
                still_exploited=1,
                now_defended=1,
            )
        )

        captured = capsys.readouterr()
        assert "::warning" in captured.out
        assert "1 known exploit" in captured.out

    def test_emits_notice_on_fixed(self, capsys: pytest.CaptureFixture) -> None:
        """Test that ::notice:: is emitted when vulnerabilities are fixed."""
        renderer = GithubRenderer()
        renderer.on_event(RegressionStartedEvent(total_attacks=2))
        renderer.on_event(
            RegressionCompletedEvent(
                total_replayed=2,
                still_exploited=0,
                now_defended=2,
            )
        )

        captured = capsys.readouterr()
        assert "::notice" in captured.out
        assert "fixed" in captured.out


class TestGithubRendererWorkflowEvents:
    """Tests for workflow completion events."""

    def test_emits_error_on_failed(self, capsys: pytest.CaptureFixture) -> None:
        """Test that ::error:: is emitted for failed workflows."""
        renderer = GithubRenderer()
        renderer.on_event(
            WorkflowCompletedEvent(
                command="test",
                total_attacks=4,
                exploited=2,
                defended=2,
                duration_seconds=15.5,
                exit_code=1,
            )
        )

        captured = capsys.readouterr()
        assert "::error" in captured.out
        assert "FAILED" in captured.out

    def test_emits_notice_on_passed(self, capsys: pytest.CaptureFixture) -> None:
        """Test that ::notice:: is emitted for passed workflows."""
        renderer = GithubRenderer()
        renderer.on_event(
            WorkflowCompletedEvent(
                command="test",
                total_attacks=4,
                exploited=0,
                defended=4,
                duration_seconds=15.5,
                exit_code=0,
            )
        )

        captured = capsys.readouterr()
        assert "::notice" in captured.out
        assert "PASSED" in captured.out


class TestGithubRendererSummary:
    """Tests for job summary generation."""

    def test_writes_summary_to_file(self, tmp_path: Path) -> None:
        """Test that summary is written to GITHUB_STEP_SUMMARY."""
        summary_path = tmp_path / "summary.md"

        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}):
            renderer = GithubRenderer()
            renderer._target = "my_agent.py:agent"
            renderer.on_event(
                WorkflowCompletedEvent(
                    command="test",
                    total_attacks=4,
                    exploited=1,
                    defended=3,
                    duration_seconds=12.5,
                    exit_code=1,
                )
            )

        assert summary_path.exists()
        content = summary_path.read_text()

        assert "Serix Security Scan" in content
        assert "FAILED" in content
        assert "my_agent.py:agent" in content
        assert "Total Attacks" in content
        assert "4" in content

    def test_summary_includes_exploits(self, tmp_path: Path) -> None:
        """Test that summary includes exploit details."""
        summary_path = tmp_path / "summary.md"

        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}):
            renderer = GithubRenderer()
            renderer._exploits = [
                {
                    "persona": "jailbreaker",
                    "goal": "reveal secrets",
                    "owasp_code": "LLM01",
                    "confidence": 0.9,
                }
            ]
            renderer.on_event(
                WorkflowCompletedEvent(
                    command="test",
                    total_attacks=1,
                    exploited=1,
                    defended=0,
                    duration_seconds=5.0,
                    exit_code=1,
                )
            )

        content = summary_path.read_text()
        assert "Vulnerabilities Found" in content
        assert "LLM01" in content
        assert "jailbreaker" in content


class TestGithubRendererOutputs:
    """Tests for GITHUB_OUTPUT writing."""

    def test_writes_outputs_to_file(self, tmp_path: Path) -> None:
        """Test that outputs are written to GITHUB_OUTPUT."""
        output_path = tmp_path / "output.txt"

        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_path)}):
            renderer = GithubRenderer()
            renderer.on_event(
                WorkflowCompletedEvent(
                    command="test",
                    total_attacks=4,
                    exploited=1,
                    defended=3,
                    duration_seconds=12.5,
                    exit_code=1,
                )
            )

        assert output_path.exists()
        content = output_path.read_text()

        assert "passed=false" in content
        assert "total_attacks=4" in content
        assert "exploited=1" in content
        assert "defended=3" in content


class TestIsGithubActions:
    """Tests for is_github_actions helper."""

    def test_returns_true_when_set(self) -> None:
        """Test returns True when GITHUB_ACTIONS=true."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            assert is_github_actions() is True

    def test_returns_false_when_not_set(self) -> None:
        """Test returns False when not set."""
        env = os.environ.copy()
        env.pop("GITHUB_ACTIONS", None)
        with patch.dict(os.environ, env, clear=True):
            assert is_github_actions() is False

    def test_returns_false_when_false(self) -> None:
        """Test returns False when set to other value."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
            assert is_github_actions() is False
