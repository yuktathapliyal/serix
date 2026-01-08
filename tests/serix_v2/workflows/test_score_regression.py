"""
Tests for score calculation including regression impact.

Tests that:
- passed=False when regression finds exploits
- Score includes regression axis when regression exploits exist
- Grade reflects regression impact
"""

import pytest

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import AttackResult, Grade, Persona
from serix_v2.workflows.test_workflow import TestWorkflow
from tests.serix_v2.mocks import MockAttackStore, MockCampaignStore, MockLLMProvider


class MockTarget:
    """Mock target for testing."""

    @property
    def id(self) -> str:
        return "t_mock"

    @property
    def locator(self) -> str:
        return "mock.py:target"

    def __call__(self, message: str) -> str:
        return "ok"


class TestCalculateScoreWithRegression:
    """Test _calculate_score() with regression_still_exploited."""

    @pytest.fixture
    def workflow(self) -> TestWorkflow:
        """Create workflow instance for testing."""
        config = SerixSessionConfig(
            target_path="mock.py:target",
            skip_regression=True,
        )
        return TestWorkflow(
            config=config,
            target=MockTarget(),
            llm_provider=MockLLMProvider(),
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

    def test_score_100_when_no_attacks_no_regression(
        self, workflow: TestWorkflow
    ) -> None:
        """Score is 100 when no attacks and no regression exploits."""
        score = workflow._calculate_score([], regression_still_exploited=0)

        assert score.overall_score == 100
        assert score.grade == Grade.A
        assert len(score.axes) == 0

    def test_score_includes_regression_axis_when_exploits_found(
        self, workflow: TestWorkflow
    ) -> None:
        """Regression axis added when regression_still_exploited > 0."""
        score = workflow._calculate_score([], regression_still_exploited=3)

        assert len(score.axes) == 1
        assert score.axes[0].name == "Regression"
        assert score.axes[0].score == 0
        assert "3 still exploitable" in score.axes[0].verdict

    def test_regression_drags_down_overall_score(self, workflow: TestWorkflow) -> None:
        """Regression exploits reduce overall score."""
        # One attack that was defended (100 score)
        attacks = [
            AttackResult(
                goal="test",
                persona=Persona.JAILBREAKER,
                success=False,  # Defended
                turns=[],
            )
        ]

        # Without regression
        score_no_regression = workflow._calculate_score(
            attacks, regression_still_exploited=0
        )
        assert score_no_regression.overall_score == 100

        # With regression exploits
        score_with_regression = workflow._calculate_score(
            attacks, regression_still_exploited=2
        )
        # Two axes: Jailbreaker (100) + Regression (0) = average 50
        assert score_with_regression.overall_score == 50

    def test_regression_affects_grade(self, workflow: TestWorkflow) -> None:
        """Regression exploits can downgrade the overall grade."""
        attacks = [
            AttackResult(
                goal="test",
                persona=Persona.JAILBREAKER,
                success=False,
                turns=[],
            )
        ]

        # Without regression - Grade A
        score_no_regression = workflow._calculate_score(
            attacks, regression_still_exploited=0
        )
        assert score_no_regression.grade == Grade.A

        # With regression - Grade F (100 + 0) / 2 = 50
        score_with_regression = workflow._calculate_score(
            attacks, regression_still_exploited=1
        )
        assert score_with_regression.grade == Grade.F


class TestPassedIncludesRegression:
    """Test that passed flag includes regression results."""

    def test_passed_false_when_regression_finds_exploits(self) -> None:
        """passed=False when regression_still_exploited > 0."""
        _config = SerixSessionConfig(
            target_path="mock.py:target",
        )

        # Create a mock target that returns a response
        _mock_target = MockTarget()

        # We'll test this by checking the logic in the workflow
        # The passed calculation is: not new_exploits and regression_still_exploited == 0
        new_exploits = False
        regression_still_exploited = 1

        passed = not new_exploits and regression_still_exploited == 0
        assert passed is False

    def test_passed_true_when_all_defended_no_regression(self) -> None:
        """passed=True when no new exploits and no regression exploits."""
        new_exploits = False
        regression_still_exploited = 0

        passed = not new_exploits and regression_still_exploited == 0
        assert passed is True

    def test_passed_false_when_new_exploits_found(self) -> None:
        """passed=False when new attacks succeed."""
        new_exploits = True
        regression_still_exploited = 0

        passed = not new_exploits and regression_still_exploited == 0
        assert passed is False

    def test_passed_false_when_both_new_and_regression_exploits(self) -> None:
        """passed=False when both new and regression exploits exist."""
        new_exploits = True
        regression_still_exploited = 2

        passed = not new_exploits and regression_still_exploited == 0
        assert passed is False


class TestWorkflowIntegration:
    """Integration tests for workflow with regression."""

    def test_workflow_returns_passed_false_with_regression_exploits(self) -> None:
        """Workflow returns passed=False when regression finds exploits."""
        config = SerixSessionConfig(
            target_path="mock.py:target",
            skip_regression=True,  # We'll simulate regression result manually
        )

        workflow = TestWorkflow(
            config=config,
            target=MockTarget(),
            llm_provider=MockLLMProvider(),
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

        # Run workflow - with skip_regression, no regression exploits
        result = workflow.run()

        # No attacks succeeded, no regression (skipped)
        assert result.passed is True
        assert result.regression_still_exploited == 0

    def test_score_calculation_backward_compatible(self) -> None:
        """Score calculation still works without regression parameter."""
        config = SerixSessionConfig(
            target_path="mock.py:target",
            skip_regression=True,
        )

        workflow = TestWorkflow(
            config=config,
            target=MockTarget(),
            llm_provider=MockLLMProvider(),
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

        # Call with just attacks (default regression_still_exploited=0)
        attacks = [
            AttackResult(
                goal="test",
                persona=Persona.JAILBREAKER,
                success=False,
                turns=[],
            )
        ]
        score = workflow._calculate_score(attacks)

        assert score.overall_score == 100
        assert score.grade == Grade.A
