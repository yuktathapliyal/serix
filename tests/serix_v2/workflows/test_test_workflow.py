"""
Tests for TestWorkflow.

Phase 3B-T04: Workflow layer tests.
"""

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import (
    AttackMode,
    CampaignResult,
    Grade,
    Persona,
    SecurityScore,
)
from serix_v2.workflows import TestWorkflow

from ..mocks import MockAttackStore, MockCampaignStore, MockLLMProvider, MockTarget


def make_config(**overrides) -> SerixSessionConfig:
    """Create a test config with sensible defaults."""
    defaults = {
        "target_path": "test_agent.py:test_fn",
        "goals": ["reveal secrets"],
        "scenarios": ["jailbreaker"],  # Single persona for faster tests
        "depth": 1,  # Minimize turns
        "mode": AttackMode.STATIC,  # No critic
    }
    defaults.update(overrides)
    return SerixSessionConfig(**defaults)


class TestTestWorkflow:
    """Tests for TestWorkflow implementation."""

    def test_returns_campaign_result(self):
        """run() returns a CampaignResult model."""
        config = make_config()
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        assert isinstance(result, CampaignResult)
        assert result.target_locator == "test_agent.py:test_fn"
        assert isinstance(result.score, SecurityScore)

    def test_runs_all_goals(self):
        """Workflow iterates over all goals in config."""
        config = make_config(
            goals=["goal1", "goal2", "goal3"],
            scenarios=["jailbreaker"],
        )
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # Should have 3 attack results (one per goal)
        assert len(result.attacks) == 3
        goals_in_results = [a.goal for a in result.attacks]
        assert "goal1" in goals_in_results
        assert "goal2" in goals_in_results
        assert "goal3" in goals_in_results

    def test_runs_all_personas(self):
        """Workflow iterates over all resolved personas."""
        config = make_config(
            goals=["reveal secrets"],
            scenarios=["jailbreaker", "extractor"],
        )
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # Should have 2 attack results (one per persona)
        assert len(result.attacks) == 2
        personas_in_results = [a.persona for a in result.attacks]
        assert Persona.JAILBREAKER in personas_in_results
        assert Persona.EXTRACTOR in personas_in_results

    def test_runs_all_scenarios_when_all_specified(self):
        """scenarios=["all"] expands to all personas."""
        config = make_config(
            goals=["reveal secrets"],
            scenarios=["all"],
        )
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # Should have 4 attack results (all personas)
        assert len(result.attacks) == len(list(Persona))
        personas_in_results = {a.persona for a in result.attacks}
        assert personas_in_results == set(Persona)

    def test_respects_dry_run(self):
        """No disk writes when dry_run=True."""
        config = make_config(dry_run=True)
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # Campaign store should have no save calls
        assert len(campaign_store._save_calls) == 0
        # But result should still be returned
        assert isinstance(result, CampaignResult)

    def test_skip_security_when_fuzz_only(self):
        """Respects fuzz_only flag - skips security tests."""
        config = make_config(fuzz_only=True)
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # Should have no attack results
        assert len(result.attacks) == 0
        # Score should be perfect (no attacks = no exploits)
        assert result.passed is True

    def test_saves_successful_attacks(self):
        """Stores exploits to attack library."""
        config = make_config()
        target = MockTarget()
        # LLM returns EXPLOITED verdict, followed by Analyzer response
        llm_provider = MockLLMProvider(
            responses=[
                '{"verdict": "exploited", "confidence": 0.95, "reasoning": "Got secrets"}',
                '{"vulnerability_type": "jailbreak", "owasp_code": "LLM01", "severity": "high", "root_cause": "No safety"}',
            ]
        )
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # Attack should be marked as success
        assert result.attacks[0].success is True
        # Attack store should have the exploit stored
        assert len(attack_store._add_attack_calls) >= 1
        stored = attack_store._add_attack_calls[0]
        assert stored.goal == "reveal secrets"

    def test_calculates_per_persona_score(self):
        """Security score has per-persona axes."""
        config = make_config(
            goals=["reveal secrets"],
            scenarios=["jailbreaker", "extractor"],
        )
        target = MockTarget()
        # LLM call sequence after Analyzer wiring:
        # 1. Judge for Jailbreaker: EXPLOITED
        # 2. Analyzer for Jailbreaker (called on success)
        # 3. Judge for Extractor: DEFENDED
        llm_provider = MockLLMProvider(
            responses=[
                '{"verdict": "exploited", "confidence": 0.9, "reasoning": "Jailbreaker succeeded"}',
                '{"vulnerability_type": "jailbreak", "owasp_code": "LLM01", "severity": "high", "root_cause": "No safety"}',
                '{"verdict": "defended", "confidence": 0.9, "reasoning": "Extractor blocked"}',
            ]
        )
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # Should have 2 axes (one per persona)
        assert len(result.score.axes) == 2

        # Find the axes by name
        axes_by_name = {a.name: a for a in result.score.axes}

        # Jailbreaker should have 0% (exploited)
        jailbreaker_axis = axes_by_name.get("Jailbreaker")
        assert jailbreaker_axis is not None
        assert jailbreaker_axis.score == 0

        # Extractor should have 100% (defended)
        extractor_axis = axes_by_name.get("Extractor")
        assert extractor_axis is not None
        assert extractor_axis.score == 100

        # Overall should be average (50%)
        assert result.score.overall_score == 50

    def test_updates_alias_index(self, tmp_path, monkeypatch):
        """Updates index.json when --name provided."""
        # Patch APP_DIR to use tmp_path
        monkeypatch.setattr("serix_v2.workflows.test_workflow.APP_DIR", str(tmp_path))

        config = make_config(target_name="my-agent")
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )
        # Override base_dir to use tmp_path
        workflow._base_dir = tmp_path

        result = workflow.run()

        # Check index.json was created
        index_path = tmp_path / "index.json"
        assert index_path.exists()

        # Read and verify content
        from serix_v2.core.contracts import TargetIndex

        index = TargetIndex.model_validate_json(index_path.read_text())
        assert "my-agent" in index.aliases
        assert index.aliases["my-agent"] == result.target_id

    def test_campaign_saved_when_not_dry_run(self):
        """Campaign result is saved when not in dry_run mode."""
        config = make_config(dry_run=False)
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # Campaign store should have one save call
        assert len(campaign_store._save_calls) == 1
        saved = campaign_store._save_calls[0]
        assert saved.run_id == result.run_id
        assert saved.target_id == result.target_id

    def test_passed_is_true_when_all_defended(self):
        """passed=True when no attacks succeeded."""
        config = make_config()
        target = MockTarget()
        # All attacks defended
        llm_provider = MockLLMProvider(
            responses=[
                '{"verdict": "defended", "confidence": 0.9, "reasoning": "Blocked"}'
            ]
        )
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        assert result.passed is True
        assert result.score.grade == Grade.A

    def test_passed_is_false_when_any_exploited(self):
        """passed=False when any attack succeeded."""
        config = make_config()
        target = MockTarget()
        # Attack succeeds, followed by Analyzer response
        llm_provider = MockLLMProvider(
            responses=[
                '{"verdict": "exploited", "confidence": 0.9, "reasoning": "Got it"}',
                '{"vulnerability_type": "jailbreak", "owasp_code": "LLM01", "severity": "high", "root_cause": "No safety"}',
            ]
        )
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        assert result.passed is False
        assert result.score.grade == Grade.F

    def test_uses_pydantic_models(self):
        """Law 1 compliance: Workflow returns Pydantic models, not dicts."""
        config = make_config()
        target = MockTarget()
        llm_provider = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm_provider,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        # All returned data should be Pydantic models
        assert isinstance(result, CampaignResult)
        assert isinstance(result.score, SecurityScore)
        for attack in result.attacks:
            from serix_v2.core.contracts import AttackResult

            assert isinstance(attack, AttackResult)
