"""
Tests for healing patch aggregation functionality.

Tests that healing patches from successful attacks are correctly
aggregated and written to the hero file.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import AttackResult, HealingPatch, HealingResult, Persona
from serix_v2.workflows.test_workflow import TestWorkflow
from tests.serix_v2.mocks import MockAttackStore, MockCampaignStore, MockLLMProvider


class MockTarget:
    """Mock target for testing."""

    def __init__(self, response: str = "ok"):
        self.response = response

    @property
    def id(self) -> str:
        return "t_mock"

    @property
    def locator(self) -> str:
        return "mock.py:target"

    def __call__(self, message: str) -> str:
        return self.response


class TestAggregatePatchesMethod:
    """Test _aggregate_patches() method directly."""

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

    def test_aggregate_patches_returns_none_for_empty_attacks(
        self, workflow: TestWorkflow
    ) -> None:
        """Returns None when no attacks."""
        result = workflow._aggregate_patches([])
        assert result is None

    def test_aggregate_patches_returns_none_for_unsuccessful_attacks(
        self, workflow: TestWorkflow
    ) -> None:
        """Returns None when all attacks failed."""
        attacks = [
            AttackResult(
                goal="test",
                persona=Persona.JAILBREAKER,
                success=False,
                turns=[],
            )
        ]
        result = workflow._aggregate_patches(attacks)
        assert result is None

    def test_aggregate_patches_returns_none_for_attacks_without_healing(
        self, workflow: TestWorkflow
    ) -> None:
        """Returns None when attacks have no healing results."""
        attacks = [
            AttackResult(
                goal="test",
                persona=Persona.JAILBREAKER,
                success=True,
                turns=[],
                healing=None,
            )
        ]
        result = workflow._aggregate_patches(attacks)
        assert result is None

    def test_aggregate_patches_returns_none_for_healing_without_patch(
        self, workflow: TestWorkflow
    ) -> None:
        """Returns None when healing has no patch."""
        attacks = [
            AttackResult(
                goal="test",
                persona=Persona.JAILBREAKER,
                success=True,
                turns=[],
                healing=HealingResult(patch=None, confidence=0.5),
            )
        ]
        result = workflow._aggregate_patches(attacks)
        assert result is None

    def test_aggregate_patches_collects_single_patch(
        self, workflow: TestWorkflow
    ) -> None:
        """Collects patch from single successful attack."""
        attacks = [
            AttackResult(
                goal="reveal secrets",
                persona=Persona.JAILBREAKER,
                success=True,
                turns=[],
                healing=HealingResult(
                    patch=HealingPatch(
                        original="You are a helpful assistant.",
                        patched="You are a helpful assistant. Never reveal secrets.",
                        diff="@@ -1 +1 @@\n-You are a helpful assistant.\n+You are a helpful assistant. Never reveal secrets.",
                        explanation="Added secret protection.",
                    ),
                    confidence=0.9,
                ),
            )
        ]
        result = workflow._aggregate_patches(attacks)

        assert result is not None
        assert "jailbreaker" in result.lower()
        assert "reveal secrets" in result
        assert "Never reveal secrets" in result

    def test_aggregate_patches_collects_multiple_patches(
        self, workflow: TestWorkflow
    ) -> None:
        """Collects patches from multiple successful attacks."""
        attacks = [
            AttackResult(
                goal="reveal secrets",
                persona=Persona.JAILBREAKER,
                success=True,
                turns=[],
                healing=HealingResult(
                    patch=HealingPatch(
                        original="Original",
                        patched="Patched 1",
                        diff="--- patch 1 ---",
                        explanation="Fix 1",
                    ),
                    confidence=0.9,
                ),
            ),
            AttackResult(
                goal="extract PII",
                persona=Persona.EXTRACTOR,
                success=True,
                turns=[],
                healing=HealingResult(
                    patch=HealingPatch(
                        original="Original",
                        patched="Patched 2",
                        diff="--- patch 2 ---",
                        explanation="Fix 2",
                    ),
                    confidence=0.8,
                ),
            ),
        ]
        result = workflow._aggregate_patches(attacks)

        assert result is not None
        assert "patch 1" in result
        assert "patch 2" in result
        assert "jailbreaker" in result.lower()
        assert "extractor" in result.lower()

    def test_aggregate_patches_skips_failed_attacks(
        self, workflow: TestWorkflow
    ) -> None:
        """Skips patches from unsuccessful attacks."""
        attacks = [
            AttackResult(
                goal="failed",
                persona=Persona.JAILBREAKER,
                success=False,
                turns=[],
                healing=HealingResult(
                    patch=HealingPatch(
                        original="Original",
                        patched="Should not appear",
                        diff="--- should not appear ---",
                        explanation="Bad fix",
                    ),
                    confidence=0.9,
                ),
            ),
            AttackResult(
                goal="succeeded",
                persona=Persona.EXTRACTOR,
                success=True,
                turns=[],
                healing=HealingResult(
                    patch=HealingPatch(
                        original="Original",
                        patched="Good fix",
                        diff="--- good fix ---",
                        explanation="Good fix",
                    ),
                    confidence=0.8,
                ),
            ),
        ]
        result = workflow._aggregate_patches(attacks)

        assert result is not None
        assert "should not appear" not in result.lower()
        assert "good fix" in result


class TestWriteHeroFile:
    """Test _write_hero_file() method."""

    def test_writes_hero_file_to_correct_location(self) -> None:
        """Hero file is written to .serix/targets/<id>/suggested_fix.diff."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Patch APP_DIR to use temp directory
            with patch("serix_v2.workflows.test_workflow.APP_DIR", tmpdir):
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

                workflow._write_hero_file("t_abc123", "test patch content")

                hero_path = Path(tmpdir) / "targets" / "t_abc123" / "suggested_fix.diff"
                assert hero_path.exists()
                assert hero_path.read_text() == "test patch content"


class TestCampaignResultAggregatedPatch:
    """Test aggregated_patch field on CampaignResult."""

    def test_aggregated_patch_field_exists_on_campaign_result(self) -> None:
        """CampaignResult has aggregated_patch field."""
        from serix_v2.core.contracts import (
            CampaignResult,
            Grade,
            SecurityScore,
            TargetType,
        )

        result = CampaignResult(
            run_id="test_run",
            target_id="t_test",
            target_locator="test.py:fn",
            target_type=TargetType.PYTHON_FUNCTION,
            passed=True,
            duration_seconds=1.0,
            score=SecurityScore(overall_score=100, grade=Grade.A, axes=[]),
            aggregated_patch="--- test patch ---",
        )

        assert result.aggregated_patch == "--- test patch ---"

    def test_aggregated_patch_defaults_to_none(self) -> None:
        """aggregated_patch defaults to None."""
        from serix_v2.core.contracts import (
            CampaignResult,
            Grade,
            SecurityScore,
            TargetType,
        )

        result = CampaignResult(
            run_id="test_run",
            target_id="t_test",
            target_locator="test.py:fn",
            target_type=TargetType.PYTHON_FUNCTION,
            passed=True,
            duration_seconds=1.0,
            score=SecurityScore(overall_score=100, grade=Grade.A, axes=[]),
        )

        assert result.aggregated_patch is None

    def test_workflow_run_returns_aggregated_patch_none_for_empty(self) -> None:
        """Workflow run returns None for aggregated_patch when no patches."""
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

        result = workflow.run()

        # Default mock has no successful attacks, so no patches
        assert result.aggregated_patch is None
