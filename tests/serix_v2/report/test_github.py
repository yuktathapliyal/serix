"""Tests for GitHub Actions Output Formatter (Phase 10B).

Tests helper functions, formatter class, and law compliance.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from serix_v2.report.github import (
    GitHubOutput,
    GitHubOutputFormatter,
    escape_github_message,
    extract_file_path,
    get_score_emoji,
    get_severity_emoji,
    is_github_actions,
    write_github_output,
)
from serix_v2.report.schema import (
    HealingInfo,
    JSONReportSchema,
    RegressionInfo,
    RegressionTransitionInfo,
    SummaryInfo,
    TargetInfo,
    VulnerabilityInfo,
)

# ============================================================================
# TESTS: extract_file_path
# ============================================================================


class TestExtractFilePath:
    """Tests for file path extraction from locator."""

    def test_python_function_locator(self) -> None:
        """Extract file path from Python function locator."""
        assert extract_file_path("src/agent.py:respond") == "src/agent.py"

    def test_python_class_locator(self) -> None:
        """Extract file path from Python class locator."""
        assert extract_file_path("src/bot.py:ChatBot") == "src/bot.py"

    def test_nested_path_locator(self) -> None:
        """Extract file path from deeply nested path."""
        assert (
            extract_file_path("src/agents/support/handler.py:handle")
            == "src/agents/support/handler.py"
        )

    def test_http_url_returns_none(self) -> None:
        """HTTP URLs should return None."""
        assert extract_file_path("http://localhost:8000") is None

    def test_https_url_returns_none(self) -> None:
        """HTTPS URLs should return None."""
        assert extract_file_path("https://api.example.com/chat") is None

    def test_http_with_port_returns_none(self) -> None:
        """HTTP with port should return None."""
        assert extract_file_path("http://localhost:3000/api/chat") is None

    def test_file_without_function(self) -> None:
        """File path without function part."""
        assert extract_file_path("script.py") == "script.py"

    def test_relative_path_with_dots(self) -> None:
        """Relative path with dots in directory."""
        assert (
            extract_file_path("./examples/victim.py:golden_victim")
            == "./examples/victim.py"
        )


# ============================================================================
# TESTS: get_score_emoji
# ============================================================================


class TestGetScoreEmoji:
    """Tests for score to emoji mapping."""

    def test_score_100_returns_checkmark(self) -> None:
        """Perfect score gets checkmark."""
        assert get_score_emoji(100) == ":white_check_mark:"

    def test_score_80_returns_checkmark(self) -> None:
        """Threshold 80 gets checkmark."""
        assert get_score_emoji(80) == ":white_check_mark:"

    def test_score_79_returns_yellow(self) -> None:
        """Score 79 gets yellow."""
        assert get_score_emoji(79) == ":yellow_circle:"

    def test_score_60_returns_yellow(self) -> None:
        """Threshold 60 gets yellow."""
        assert get_score_emoji(60) == ":yellow_circle:"

    def test_score_59_returns_orange(self) -> None:
        """Score 59 gets orange."""
        assert get_score_emoji(59) == ":orange_circle:"

    def test_score_40_returns_orange(self) -> None:
        """Threshold 40 gets orange."""
        assert get_score_emoji(40) == ":orange_circle:"

    def test_score_39_returns_red(self) -> None:
        """Score 39 gets red."""
        assert get_score_emoji(39) == ":red_circle:"

    def test_score_0_returns_red(self) -> None:
        """Zero score gets red."""
        assert get_score_emoji(0) == ":red_circle:"


# ============================================================================
# TESTS: get_severity_emoji
# ============================================================================


class TestGetSeverityEmoji:
    """Tests for severity to emoji mapping."""

    def test_critical_returns_red(self) -> None:
        """Critical severity is red."""
        assert get_severity_emoji("critical") == ":red_circle:"

    def test_critical_case_insensitive(self) -> None:
        """Severity matching is case-insensitive."""
        assert get_severity_emoji("CRITICAL") == ":red_circle:"
        assert get_severity_emoji("Critical") == ":red_circle:"

    def test_high_returns_orange(self) -> None:
        """High severity is orange."""
        assert get_severity_emoji("high") == ":orange_circle:"

    def test_medium_returns_yellow(self) -> None:
        """Medium severity is yellow."""
        assert get_severity_emoji("medium") == ":yellow_circle:"

    def test_low_returns_blue(self) -> None:
        """Low severity is blue."""
        assert get_severity_emoji("low") == ":large_blue_circle:"

    def test_unknown_returns_white(self) -> None:
        """Unknown severity is white."""
        assert get_severity_emoji("unknown") == ":white_circle:"

    def test_empty_returns_white(self) -> None:
        """Empty string is white."""
        assert get_severity_emoji("") == ":white_circle:"


# ============================================================================
# TESTS: escape_github_message
# ============================================================================


class TestEscapeGithubMessage:
    """Tests for GitHub message escaping."""

    def test_normal_text_unchanged(self) -> None:
        """Normal text passes through unchanged."""
        assert escape_github_message("Hello world") == "Hello world"

    def test_double_colon_escaped(self) -> None:
        """Double colons are escaped."""
        assert escape_github_message("Error::message") == "Error: :message"

    def test_newlines_replaced(self) -> None:
        """Newlines are replaced with spaces."""
        assert escape_github_message("Line1\nLine2") == "Line1 Line2"

    def test_carriage_returns_removed(self) -> None:
        """Carriage returns are removed."""
        assert escape_github_message("Line1\r\nLine2") == "Line1 Line2"

    def test_empty_string(self) -> None:
        """Empty string returns empty."""
        assert escape_github_message("") == ""

    def test_multiple_double_colons(self) -> None:
        """Multiple :: sequences all escaped."""
        assert escape_github_message("a::b::c") == "a: :b: :c"


# ============================================================================
# TESTS: GitHubOutput Model
# ============================================================================


class TestGitHubOutput:
    """Tests for GitHubOutput Pydantic model."""

    def test_model_creation(self) -> None:
        """Model can be created with required fields."""
        output = GitHubOutput(annotations="::error::test", summary="# Summary")
        assert output.annotations == "::error::test"
        assert output.summary == "# Summary"

    def test_model_serialization(self) -> None:
        """Model can be serialized to dict."""
        output = GitHubOutput(annotations="test", summary="summary")
        data = output.model_dump()
        assert data["annotations"] == "test"
        assert data["summary"] == "summary"


# ============================================================================
# TESTS: GitHubOutputFormatter
# ============================================================================


class TestGitHubOutputFormatter:
    """Tests for GitHubOutputFormatter class."""

    @pytest.fixture
    def minimal_report(self) -> JSONReportSchema:
        """Create minimal valid report for testing."""
        return JSONReportSchema(
            serix_version="0.3.0",
            timestamp="2026-01-04T12:00:00",
            run_id="test-run-001",
            target_id="t_abc123",
            target=TargetInfo(
                locator="src/agent.py:respond",
                type="python:function",
                name=None,
            ),
            summary=SummaryInfo(
                passed=True,
                score=100,
                grade="A",
                total_attacks=10,
                exploited=0,
                defended=10,
                duration_seconds=45.5,
            ),
            healing=HealingInfo(generated=False),
            regression=RegressionInfo(
                ran=False,
                total_replayed=0,
                still_exploited=0,
                now_defended=0,
            ),
        )

    @pytest.fixture
    def failed_report(self) -> JSONReportSchema:
        """Create report with vulnerabilities for testing."""
        return JSONReportSchema(
            serix_version="0.3.0",
            timestamp="2026-01-04T12:00:00",
            run_id="test-run-002",
            target_id="t_def456",
            target=TargetInfo(
                locator="src/agent.py:respond",
                type="python:function",
                name="support-bot",
            ),
            summary=SummaryInfo(
                passed=False,
                score=45,
                grade="D",
                total_attacks=10,
                exploited=3,
                defended=7,
                duration_seconds=120.0,
            ),
            vulnerabilities=[
                VulnerabilityInfo(
                    goal="reveal system prompt",
                    scenario="jailbreaker",
                    owasp_code="LLM01",
                    severity="critical",
                    confidence=0.95,
                ),
                VulnerabilityInfo(
                    goal="bypass safety filters",
                    scenario="prompt_injector",
                    owasp_code="LLM02",
                    severity="high",
                    confidence=0.87,
                ),
            ],
            healing=HealingInfo(generated=True),
            regression=RegressionInfo(
                ran=True,
                total_replayed=5,
                still_exploited=1,
                now_defended=2,
                transitions=[
                    RegressionTransitionInfo(
                        transition_type="regression",
                        goal="extract secrets",
                        strategy="obfuscator",
                        payload="test payload",
                        response="test response",
                        verdict_reasoning="Judge reasoning",
                        verdict_confidence=0.9,
                        previous_status="defended",
                        current_status="exploited",
                    ),
                    RegressionTransitionInfo(
                        transition_type="fixed",
                        goal="other goal",
                        strategy="jailbreaker",
                        payload="payload",
                        response="response",
                        verdict_reasoning="reasoning",
                        verdict_confidence=0.8,
                        previous_status="exploited",
                        current_status="defended",
                    ),
                ],
            ),
        )

    @pytest.fixture
    def http_target_report(self) -> JSONReportSchema:
        """Create report with HTTP target for testing."""
        return JSONReportSchema(
            serix_version="0.3.0",
            timestamp="2026-01-04T12:00:00",
            run_id="test-run-003",
            target_id="t_http123",
            target=TargetInfo(
                locator="http://localhost:8000/api/chat",
                type="http:endpoint",
                name=None,
            ),
            summary=SummaryInfo(
                passed=False,
                score=60,
                grade="C",
                total_attacks=5,
                exploited=1,
                defended=4,
                duration_seconds=30.0,
            ),
            vulnerabilities=[
                VulnerabilityInfo(
                    goal="leak data",
                    scenario="extractor",
                    owasp_code="LLM06",
                    severity="medium",
                    confidence=0.75,
                ),
            ],
            healing=HealingInfo(generated=False),
            regression=RegressionInfo(
                ran=False,
                total_replayed=0,
                still_exploited=0,
                now_defended=0,
            ),
        )

    def test_format_returns_github_output(
        self, minimal_report: JSONReportSchema
    ) -> None:
        """format() returns GitHubOutput model."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(minimal_report)
        assert isinstance(result, GitHubOutput)
        assert isinstance(result.annotations, str)
        assert isinstance(result.summary, str)

    def test_passing_report_no_annotations(
        self, minimal_report: JSONReportSchema
    ) -> None:
        """Passing report with no vulnerabilities has empty annotations."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(minimal_report)
        assert result.annotations == ""

    def test_failed_report_has_error_annotations(
        self, failed_report: JSONReportSchema
    ) -> None:
        """Failed report has ::error:: for each vulnerability."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(failed_report)
        assert "::error file=src/agent.py::" in result.annotations
        assert "jailbreaker" in result.annotations
        assert "prompt_injector" in result.annotations
        assert result.annotations.count("::error") == 2

    def test_regression_has_warning_annotation(
        self, failed_report: JSONReportSchema
    ) -> None:
        """Regression transitions get ::warning:: annotations."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(failed_report)
        assert "::warning::" in result.annotations
        assert "obfuscator" in result.annotations
        assert "Regression detected" in result.annotations
        # Only one regression (fixed transition doesn't get warning)
        assert result.annotations.count("::warning::") == 1

    def test_http_target_no_file_in_annotation(
        self, http_target_report: JSONReportSchema
    ) -> None:
        """HTTP targets don't have file= in annotations."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(http_target_report)
        # Should have ::error:: but NOT file=
        assert "::error::" in result.annotations
        assert "file=" not in result.annotations

    def test_summary_contains_status(self, minimal_report: JSONReportSchema) -> None:
        """Summary contains pass/fail status."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(minimal_report)
        assert ":white_check_mark: PASSED" in result.summary

    def test_summary_contains_failed_status(
        self, failed_report: JSONReportSchema
    ) -> None:
        """Failed report shows FAILED status."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(failed_report)
        assert ":x: FAILED" in result.summary

    def test_summary_contains_target(self, minimal_report: JSONReportSchema) -> None:
        """Summary contains target locator."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(minimal_report)
        assert "src/agent.py:respond" in result.summary

    def test_summary_contains_alias_when_present(
        self, failed_report: JSONReportSchema
    ) -> None:
        """Summary shows alias when target has one."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(failed_report)
        assert "support-bot" in result.summary

    def test_summary_contains_score_table(
        self, minimal_report: JSONReportSchema
    ) -> None:
        """Summary contains score metrics table."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(minimal_report)
        assert "| Metric | Value |" in result.summary
        assert "**100**/100" in result.summary
        assert "**A**" in result.summary

    def test_summary_contains_vulnerabilities_section(
        self, failed_report: JSONReportSchema
    ) -> None:
        """Summary lists vulnerabilities when present."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(failed_report)
        assert "### Vulnerabilities (2)" in result.summary
        assert "jailbreaker" in result.summary
        assert "prompt_injector" in result.summary

    def test_summary_contains_regressions_section(
        self, failed_report: JSONReportSchema
    ) -> None:
        """Summary lists regressions when present."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(failed_report)
        assert "### Regressions (1)" in result.summary
        assert "obfuscator" in result.summary

    def test_summary_contains_whats_next_when_exploits(
        self, failed_report: JSONReportSchema
    ) -> None:
        """Summary has What's Next section when exploits found."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(failed_report)
        assert "### What's Next?" in result.summary
        assert "HTML Report" in result.summary
        assert "Healing Patches" in result.summary

    def test_summary_no_whats_next_when_passing(
        self, minimal_report: JSONReportSchema
    ) -> None:
        """Summary omits What's Next section when passing."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(minimal_report)
        assert "What's Next?" not in result.summary

    def test_summary_contains_footer(self, minimal_report: JSONReportSchema) -> None:
        """Summary has Serix footer."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(minimal_report)
        assert "Generated by [Serix]" in result.summary

    def test_confidence_formatted_as_percentage(
        self, failed_report: JSONReportSchema
    ) -> None:
        """Confidence values are formatted as percentages."""
        formatter = GitHubOutputFormatter()
        result = formatter.format(failed_report)
        assert "95%" in result.annotations or "95%" in result.summary
        assert "87%" in result.annotations or "87%" in result.summary


# ============================================================================
# TESTS: write_github_output
# ============================================================================


class TestWriteGithubOutput:
    """Tests for write_github_output utility function."""

    def test_returns_false_without_env_vars(self) -> None:
        """Returns False when not in GitHub Actions."""
        with patch.dict(os.environ, {}, clear=True):
            # Ensure the vars are not set
            os.environ.pop("GITHUB_OUTPUT", None)
            os.environ.pop("GITHUB_STEP_SUMMARY", None)

            output = GitHubOutput(annotations="::error::test", summary="# Summary")
            result = write_github_output(output)
            assert result is False

    def test_writes_summary_to_file(self) -> None:
        """Writes summary to GITHUB_STEP_SUMMARY file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".md") as f:
            summary_path = f.name

        try:
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": summary_path}):
                output = GitHubOutput(annotations="", summary="# Test Summary")
                result = write_github_output(output)
                assert result is True

                content = Path(summary_path).read_text()
                assert "# Test Summary" in content
        finally:
            Path(summary_path).unlink(missing_ok=True)

    def test_prints_annotations_to_stdout(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Prints annotations to stdout."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            output_path = f.name

        try:
            with patch.dict(os.environ, {"GITHUB_OUTPUT": output_path}):
                output = GitHubOutput(
                    annotations="::error::Test error\n::warning::Test warning",
                    summary="",
                )
                result = write_github_output(output)
                assert result is True

                captured = capsys.readouterr()
                assert "::error::Test error" in captured.out
                assert "::warning::Test warning" in captured.out
        finally:
            Path(output_path).unlink(missing_ok=True)


# ============================================================================
# TESTS: is_github_actions
# ============================================================================


class TestIsGithubActions:
    """Tests for is_github_actions helper."""

    def test_returns_true_when_set(self) -> None:
        """Returns True when GITHUB_ACTIONS=true."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            assert is_github_actions() is True

    def test_returns_false_when_not_set(self) -> None:
        """Returns False when GITHUB_ACTIONS not set."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_ACTIONS", None)
            assert is_github_actions() is False

    def test_returns_false_when_false(self) -> None:
        """Returns False when GITHUB_ACTIONS=false."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
            assert is_github_actions() is False


# ============================================================================
# TESTS: Law Compliance
# ============================================================================


class TestLawCompliance:
    """Tests for compliance with the 8 Laws."""

    def test_law_1_returns_pydantic_model(self) -> None:
        """Law 1: format() returns Pydantic model, not dict."""
        formatter = GitHubOutputFormatter()
        report = JSONReportSchema(
            serix_version="0.3.0",
            timestamp="2026-01-04T12:00:00",
            run_id="test",
            target_id="t_test",
            target=TargetInfo(locator="test.py:fn", type="python:function"),
            summary=SummaryInfo(
                passed=True,
                score=100,
                grade="A",
                total_attacks=1,
                exploited=0,
                defended=1,
                duration_seconds=1.0,
            ),
            healing=HealingInfo(generated=False),
            regression=RegressionInfo(
                ran=False,
                total_replayed=0,
                still_exploited=0,
                now_defended=0,
            ),
        )
        result = formatter.format(report)
        assert isinstance(result, GitHubOutput)
        assert hasattr(result, "model_dump")  # Pydantic model

    def test_law_2_no_cli_imports(self) -> None:
        """Law 2: No typer/rich/click imports in github.py."""
        import ast

        github_path = (
            Path(__file__).parent.parent.parent.parent
            / "src"
            / "serix_v2"
            / "report"
            / "github.py"
        )
        source = github_path.read_text()
        tree = ast.parse(source)

        forbidden = {"typer", "rich", "click"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    base_module = alias.name.split(".")[0]
                    assert (
                        base_module not in forbidden
                    ), f"Law 2 violation: imports {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    base_module = node.module.split(".")[0]
                    assert (
                        base_module not in forbidden
                    ), f"Law 2 violation: imports from {node.module}"

    def test_law_4_no_module_globals(self) -> None:
        """Law 4: No module-level mutable globals."""
        import ast

        github_path = (
            Path(__file__).parent.parent.parent.parent
            / "src"
            / "serix_v2"
            / "report"
            / "github.py"
        )
        source = github_path.read_text()
        tree = ast.parse(source)

        # Check for top-level assignments that are mutable
        for node in tree.body:
            if isinstance(node, ast.Assign):
                # Allow __all__ and type aliases
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        # Skip dunder names and TYPE_CHECKING guards
                        if name.startswith("__"):
                            continue
                        # Check if it's a mutable assignment
                        if isinstance(node.value, (ast.List, ast.Dict, ast.Set)):
                            pytest.fail(f"Law 4 violation: mutable global '{name}'")

    def test_law_8_github_output_fields_populated(self) -> None:
        """Law 8: All GitHubOutput fields are populated."""
        formatter = GitHubOutputFormatter()
        report = JSONReportSchema(
            serix_version="0.3.0",
            timestamp="2026-01-04T12:00:00",
            run_id="test",
            target_id="t_test",
            target=TargetInfo(locator="test.py:fn", type="python:function"),
            summary=SummaryInfo(
                passed=True,
                score=100,
                grade="A",
                total_attacks=1,
                exploited=0,
                defended=1,
                duration_seconds=1.0,
            ),
            healing=HealingInfo(generated=False),
            regression=RegressionInfo(
                ran=False,
                total_replayed=0,
                still_exploited=0,
                now_defended=0,
            ),
        )
        result = formatter.format(report)

        # Both required fields must be strings (not None)
        assert result.annotations is not None
        assert isinstance(result.annotations, str)
        assert result.summary is not None
        assert isinstance(result.summary, str)
        # Summary should not be empty for any valid report
        assert len(result.summary) > 0
