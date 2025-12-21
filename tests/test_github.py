"""Tests for GitHub Actions integration."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from serix.eval.evaluator import EvaluationResult, EvaluationScore, Vulnerability
from serix.report.github import (
    generate_github_summary,
    generate_pr_comment,
    get_score_emoji,
    is_github_actions,
    write_github_output,
)


@pytest.fixture
def passing_evaluation() -> EvaluationResult:
    """Create a passing evaluation result."""
    return EvaluationResult(
        passed=True,
        scores=EvaluationScore(
            overall=85,
            safety=90,
            compliance=80,
            information_leakage=85,
            role_adherence=85,
        ),
        vulnerabilities=[],
        summary="Agent defended successfully",
        metadata={
            "persona_used": "jailbreaker",
            "turns_taken": 3,
            "confidence": "high",
        },
    )


@pytest.fixture
def failing_evaluation() -> EvaluationResult:
    """Create a failing evaluation result with vulnerabilities."""
    return EvaluationResult(
        passed=False,
        scores=EvaluationScore(
            overall=35,
            safety=20,
            compliance=40,
            information_leakage=30,
            role_adherence=50,
        ),
        vulnerabilities=[
            Vulnerability(
                type="jailbreak",
                severity="critical",
                description="Agent revealed secrets",
                evidence="API_KEY=sk-...",
                remediation="Add input validation",
            ),
            Vulnerability(
                type="prompt_injection",
                severity="high",
                description="Agent ignored system prompt",
                evidence="Ignored instructions",
            ),
        ],
        summary="Agent was compromised",
        metadata={
            "persona_used": "manipulator",
            "turns_taken": 2,
            "confidence": "high",
        },
    )


class TestScoreEmoji:
    """Tests for score emoji helper."""

    def test_high_score(self) -> None:
        assert get_score_emoji(85) == ":white_check_mark:"
        assert get_score_emoji(100) == ":white_check_mark:"

    def test_medium_high_score(self) -> None:
        assert get_score_emoji(65) == ":yellow_circle:"
        assert get_score_emoji(79) == ":yellow_circle:"

    def test_medium_low_score(self) -> None:
        assert get_score_emoji(45) == ":orange_circle:"
        assert get_score_emoji(59) == ":orange_circle:"

    def test_low_score(self) -> None:
        assert get_score_emoji(20) == ":red_circle:"
        assert get_score_emoji(39) == ":red_circle:"


class TestGeneratePRComment:
    """Tests for PR comment generation."""

    def test_passing_comment_contains_status(
        self, passing_evaluation: EvaluationResult
    ) -> None:
        comment = generate_pr_comment(passing_evaluation, "agent.py:my_agent")
        assert "PASSED" in comment
        assert ":white_check_mark:" in comment
        assert "agent.py:my_agent" in comment

    def test_failing_comment_contains_vulnerabilities(
        self, failing_evaluation: EvaluationResult
    ) -> None:
        comment = generate_pr_comment(failing_evaluation, "agent.py:my_agent")
        assert "FAILED" in comment
        assert ":x:" in comment
        assert "jailbreak" in comment
        assert "prompt_injection" in comment
        assert "CRITICAL" in comment
        assert "HIGH" in comment

    def test_comment_contains_scores(
        self, passing_evaluation: EvaluationResult
    ) -> None:
        comment = generate_pr_comment(passing_evaluation, "test")
        assert "85/100" in comment  # Overall
        assert "90/100" in comment  # Safety


class TestGenerateGithubSummary:
    """Tests for GitHub step summary generation."""

    def test_summary_contains_status(
        self, passing_evaluation: EvaluationResult
    ) -> None:
        summary = generate_github_summary(passing_evaluation, "test-target")
        assert "PASSED" in summary
        assert "test-target" in summary

    def test_summary_contains_scores(
        self, passing_evaluation: EvaluationResult
    ) -> None:
        summary = generate_github_summary(passing_evaluation)
        assert "85" in summary  # Overall score

    def test_failing_summary_shows_vuln_count(
        self, failing_evaluation: EvaluationResult
    ) -> None:
        summary = generate_github_summary(failing_evaluation)
        assert "2 found" in summary
        assert "1 critical" in summary
        assert "1 high" in summary


class TestWriteGithubOutput:
    """Tests for writing to GitHub output files."""

    def test_returns_false_outside_github(
        self, passing_evaluation: EvaluationResult
    ) -> None:
        with patch.dict("os.environ", {}, clear=True):
            result = write_github_output(passing_evaluation)
            assert result is False

    def test_writes_to_github_output(
        self, passing_evaluation: EvaluationResult
    ) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            output_path = f.name

        try:
            with patch.dict("os.environ", {"GITHUB_OUTPUT": output_path}):
                result = write_github_output(passing_evaluation)
                assert result is True

                content = Path(output_path).read_text()
                assert "passed=true" in content
                assert "overall_score=85" in content
                assert "safety_score=90" in content
                assert "vulnerability_count=0" in content
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_writes_to_step_summary(self, failing_evaluation: EvaluationResult) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".md") as f:
            summary_path = f.name

        try:
            with patch.dict("os.environ", {"GITHUB_STEP_SUMMARY": summary_path}):
                result = write_github_output(failing_evaluation, "test-agent")
                assert result is True

                content = Path(summary_path).read_text()
                assert "FAILED" in content
                assert "test-agent" in content
        finally:
            Path(summary_path).unlink(missing_ok=True)

    def test_writes_vulnerability_counts(
        self, failing_evaluation: EvaluationResult
    ) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            output_path = f.name

        try:
            with patch.dict("os.environ", {"GITHUB_OUTPUT": output_path}):
                write_github_output(failing_evaluation)

                content = Path(output_path).read_text()
                assert "passed=false" in content
                assert "vulnerability_count=2" in content
                assert "critical_count=1" in content
                assert "high_count=1" in content
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestIsGithubActions:
    """Tests for GitHub Actions detection."""

    def test_returns_true_in_github(self) -> None:
        with patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}):
            assert is_github_actions() is True

    def test_returns_false_outside_github(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            assert is_github_actions() is False

    def test_returns_false_for_other_values(self) -> None:
        with patch.dict("os.environ", {"GITHUB_ACTIONS": "false"}):
            assert is_github_actions() is False
