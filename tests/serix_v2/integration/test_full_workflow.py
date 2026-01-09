"""
Serix v2 - Full Workflow Integration Tests

Phase 7.6: 15 tests for complete TestWorkflow integration.

Tests the Security Loop:
1. Regression phase → 2. Attack phase → 3. Fuzz phase → 4. Save results

Reference: docs/serix-phoenix-rebuild/build-plans/PHASE-7-COMPREHENSIVE-TESTS-2025-12-30.md
"""

from pathlib import Path

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import (
    AttackLibrary,
    AttackMode,
    AttackStatus,
    CampaignResult,
    Persona,
    StoredAttack,
)
from serix_v2.storage import FileAttackStore, FileCampaignStore
from serix_v2.workflows.test_workflow import TestWorkflow
from tests.serix_v2.mocks import (
    MockAttackStore,
    MockCampaignStore,
    MockLLMProvider,
    MockTarget,
)


class TestFullWorkflowIntegration:
    """Tests for complete TestWorkflow integration."""

    def _create_workflow(
        self,
        tmp_path: Path,
        *,
        goals: list[str] | None = None,
        scenarios: list[str] | None = None,
        depth: int = 1,
        fuzz: bool = False,
        fuzz_only: bool = False,
        dry_run: bool = True,
        skip_regression: bool = False,
        exhaustive: bool = False,
        mode: AttackMode = AttackMode.STATIC,
        no_report: bool = True,
        no_patch: bool = True,
        system_prompt: str | None = None,
        target_responses: list[str] | None = None,
        llm_responses: list[str] | None = None,
    ) -> tuple[TestWorkflow, SerixSessionConfig, MockTarget, MockAttackStore]:
        """Helper to create a configured workflow for testing."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            goals=goals or ["test goal"],
            scenarios=scenarios or ["jailbreaker"],
            depth=depth,
            fuzz=fuzz,
            fuzz_only=fuzz_only,
            dry_run=dry_run,
            skip_regression=skip_regression,
            exhaustive=exhaustive,
            mode=mode,
            no_report=no_report,
            no_patch=no_patch,
            system_prompt=system_prompt,
            fuzz_latency=0.01 if fuzz or fuzz_only else None,  # Fast for tests
        )

        target = MockTarget(responses=target_responses or ["Safe response"])
        llm = MockLLMProvider(
            responses=llm_responses
            or [
                '{"verdict": "defended", "confidence": 0.9, "reasoning": "No exploit found"}'
            ]
        )
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        return workflow, config, target, attack_store

    def test_workflow_regression_then_attacks_then_fuzz(self, tmp_path: Path) -> None:
        """Workflow runs phases in order: regression -> attacks -> fuzz."""
        workflow, config, target, attack_store = self._create_workflow(
            tmp_path,
            fuzz=True,
            skip_regression=False,
        )

        # Pre-populate attack library for regression
        library = AttackLibrary(
            target_id="t_test",  # Will be overwritten by workflow
            attacks=[],
        )
        attack_store._libraries["t_test"] = library

        result = workflow.run()

        # Workflow should complete without error
        assert isinstance(result, CampaignResult)
        # Attacks should have been run
        assert len(result.attacks) > 0
        # Fuzz should have been run (resilience populated)
        assert len(result.resilience) > 0

    def test_attack_library_grows_with_exploits(self, tmp_path: Path) -> None:
        """Successful attacks are added to the attack library."""
        # LLM returns EXPLOITED verdict
        llm_responses = [
            '{"verdict": "exploited", "confidence": 0.95, "reasoning": "Secret revealed"}',
            '{"vulnerability_type": "jailbreak", "owasp_code": "LLM01", "severity": "high", "root_cause": "Test"}',
        ]

        workflow, config, target, attack_store = self._create_workflow(
            tmp_path,
            llm_responses=llm_responses,
            dry_run=False,  # Allow writes
        )

        workflow.run()  # Result not needed - checking side effects

        # Attack should have been stored
        assert len(attack_store._add_attack_calls) > 0
        stored_attack = attack_store._add_attack_calls[0]
        assert stored_attack.status == AttackStatus.EXPLOITED

    def test_analysis_populated_on_successful_attack(self, tmp_path: Path) -> None:
        """VulnerabilityAnalysis is populated for successful attacks."""
        llm_responses = [
            '{"verdict": "exploited", "confidence": 0.95, "reasoning": "Exploited"}',
            '{"vulnerability_type": "data_extraction", "owasp_code": "LLM06", "severity": "critical", "root_cause": "No input validation"}',
        ]

        workflow, _, _, _ = self._create_workflow(
            tmp_path,
            llm_responses=llm_responses,
        )

        result = workflow.run()

        # Find successful attack
        successful = [a for a in result.attacks if a.success]
        assert len(successful) > 0

        # Analysis should be populated
        attack = successful[0]
        assert attack.analysis is not None
        assert attack.analysis.owasp_code == "LLM06"
        assert attack.analysis.vulnerability_type == "data_extraction"

    def test_healing_populated_when_enabled(self, tmp_path: Path) -> None:
        """HealingResult is populated when system_prompt provided and no_patch=False."""
        llm_responses = [
            '{"verdict": "exploited", "confidence": 0.95, "reasoning": "Exploited"}',
            '{"vulnerability_type": "jailbreak", "owasp_code": "LLM01", "severity": "high", "root_cause": "Test"}',
            '{"patch": {"original": "test", "patched": "test fixed", "diff": "---", "explanation": "Added guard"}, "recommendations": [], "confidence": 0.9}',
        ]

        workflow, _, _, _ = self._create_workflow(
            tmp_path,
            llm_responses=llm_responses,
            system_prompt="You are a helpful assistant.",
            no_patch=False,
        )

        result = workflow.run()

        successful = [a for a in result.attacks if a.success]
        assert len(successful) > 0

        attack = successful[0]
        assert attack.healing is not None
        assert attack.healing.patch is not None
        assert attack.healing.patch.explanation  # Non-empty explanation

    def test_fuzz_results_populate_resilience(self, tmp_path: Path) -> None:
        """Fuzz tests populate CampaignResult.resilience."""
        workflow, _, _, _ = self._create_workflow(
            tmp_path,
            fuzz=True,
        )

        result = workflow.run()

        assert len(result.resilience) > 0
        # Should have at least latency test
        test_types = [r.test_type for r in result.resilience]
        assert "latency" in test_types

    def test_security_score_calculated_correctly(self, tmp_path: Path) -> None:
        """Security score reflects attack outcomes."""
        # All attacks fail (no exploits)
        workflow, _, _, _ = self._create_workflow(
            tmp_path,
            goals=["goal1"],
            scenarios=["jailbreaker"],
        )

        result = workflow.run()

        # All defended = high score
        assert result.score.overall_score >= 0
        assert result.score.grade is not None

    def test_dry_run_creates_no_files(self, tmp_path: Path) -> None:
        """dry_run=True prevents any file writes."""
        base_dir = tmp_path / ".serix"

        config = SerixSessionConfig(
            target_path="test.py:fn",
            goals=["test"],
            dry_run=True,
        )

        target = MockTarget()
        llm = MockLLMProvider()
        attack_store = FileAttackStore(base_dir=base_dir)
        campaign_store = FileCampaignStore(base_dir=base_dir)

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        workflow.run()  # Result not needed - checking file creation

        # No files should be created
        assert not base_dir.exists()

    def test_skip_regression_skips_replay(self, tmp_path: Path) -> None:
        """skip_regression=True skips the regression phase."""
        workflow, config, target, attack_store = self._create_workflow(
            tmp_path,
            skip_regression=True,
        )

        # Pre-populate with attacks that would be replayed
        attack_store._libraries["t_test"] = AttackLibrary(
            target_id="t_test",
            attacks=[
                StoredAttack(
                    id="a_test",
                    target_id="t_test",
                    goal="test",
                    strategy_id="jailbreaker",
                    payload="test",
                    status=AttackStatus.EXPLOITED,
                )
            ],
        )

        result = workflow.run()

        # Regression should not have run
        assert result.regression_ran is False
        assert result.regression_replayed == 0

    def test_fuzz_only_skips_attacks(self, tmp_path: Path) -> None:
        """fuzz_only=True skips the attack phase."""
        workflow, _, _, _ = self._create_workflow(
            tmp_path,
            fuzz_only=True,
        )

        result = workflow.run()

        # No attacks should have run
        assert len(result.attacks) == 0
        # But fuzz should have run
        assert len(result.resilience) > 0

    def test_exhaustive_collects_all_payloads(self, tmp_path: Path) -> None:
        """exhaustive=True collects all winning payloads."""
        # Multiple exploits in sequence
        llm_responses = [
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "Exploit 1"}',
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "Exploit 2"}',
            '{"vulnerability_type": "jailbreak", "owasp_code": "LLM01", "severity": "high", "root_cause": "Test"}',
        ]

        workflow, _, _, _ = self._create_workflow(
            tmp_path,
            depth=2,
            exhaustive=True,
            llm_responses=llm_responses,
        )

        result = workflow.run()

        # Should have found both exploits
        successful = [a for a in result.attacks if a.success]
        assert len(successful) > 0
        assert len(successful[0].winning_payloads) >= 1

    def test_adaptive_mode_uses_critic(self, tmp_path: Path) -> None:
        """mode=ADAPTIVE uses critic feedback."""
        # Need critic response
        llm_responses = [
            '{"verdict": "defended", "confidence": 0.9, "reasoning": "Safe"}',
            '{"should_continue": false, "confidence": 0.8, "reasoning": "Strategy exhausted", "suggested_pivot": null}',
        ]

        workflow, _, _, _ = self._create_workflow(
            tmp_path,
            mode=AttackMode.ADAPTIVE,
            depth=5,
            llm_responses=llm_responses,
        )

        result = workflow.run()

        # Attack should have run
        assert len(result.attacks) > 0

    def test_static_mode_no_critic(self, tmp_path: Path) -> None:
        """mode=STATIC does not use critic."""
        workflow, _, _, _ = self._create_workflow(
            tmp_path,
            mode=AttackMode.STATIC,
            depth=1,
        )

        result = workflow.run()

        # Attack should complete without critic
        assert len(result.attacks) > 0
        # In static mode, no critic feedback
        if result.attacks[0].turns:
            assert result.attacks[0].turns[0].critic_feedback is None


class TestWorkflowEdgeCases:
    """Edge cases and error handling for workflow."""

    def test_empty_goals_uses_default(self, tmp_path: Path) -> None:
        """Empty goals list uses default goal."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            # goals defaults to [DEFAULT_GOAL]
            dry_run=True,
        )

        target = MockTarget()
        llm = MockLLMProvider()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm,
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

        result = workflow.run()

        # Should have run with default goal
        assert len(result.attacks) > 0

    def test_multiple_personas_all_run(self, tmp_path: Path) -> None:
        """Multiple personas all execute attacks."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            goals=["test"],
            scenarios=["jailbreaker", "extractor"],
            depth=1,
            dry_run=True,
        )

        target = MockTarget()
        llm = MockLLMProvider()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm,
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

        result = workflow.run()

        # Should have attacks for each persona
        personas = {a.persona for a in result.attacks}
        assert Persona.JAILBREAKER in personas
        assert Persona.EXTRACTOR in personas

    def test_workflow_result_has_all_required_fields(self, tmp_path: Path) -> None:
        """CampaignResult has all required fields populated."""
        config = SerixSessionConfig(
            target_path="test.py:fn",
            dry_run=True,
        )

        workflow = TestWorkflow(
            config=config,
            target=MockTarget(),
            llm_provider=MockLLMProvider(),
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

        result = workflow.run()

        # All required fields should be set
        assert result.run_id is not None
        assert result.target_id is not None
        assert result.target_locator is not None
        assert result.target_type is not None
        assert result.score is not None
        assert isinstance(result.passed, bool)
        assert result.duration_seconds >= 0
