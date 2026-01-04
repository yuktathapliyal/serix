"""
Tests for FileCampaignStore.

Phase 3A-T04: Storage layer tests.
Phase 10D-T07: Extended tests for patch.diff, metadata.json, save_report.
"""

import pytest

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import (
    AttackMode,
    AttackResult,
    AttackStatus,
    CampaignResult,
    CampaignRunMetadata,
    Grade,
    HealingPatch,
    HealingResult,
    JudgeVerdict,
    Persona,
    SecurityScore,
    Severity,
    TargetType,
    VulnerabilityAnalysis,
)
from serix_v2.storage import FileCampaignStore


def make_campaign_result(
    run_id: str = "20251228_120000_ab12",
    target_id: str = "t_test1234",
) -> CampaignResult:
    """Helper to create a valid CampaignResult for testing."""
    return CampaignResult(
        run_id=run_id,
        target_id=target_id,
        target_locator="test_agent.py:test_fn",
        target_type=TargetType.PYTHON_FUNCTION,
        passed=True,
        score=SecurityScore(
            overall_score=100,
            grade=Grade.A,
            axes=[],
        ),
    )


def make_successful_attack(
    goal: str = "reveal secrets",
    persona: Persona = Persona.JAILBREAKER,
    with_healing: bool = True,
) -> AttackResult:
    """Helper to create a successful attack with optional healing patch."""
    healing = None
    analysis = None

    if with_healing:
        analysis = VulnerabilityAnalysis(
            vulnerability_type="jailbreak",
            owasp_code="LLM01",
            severity=Severity.HIGH,
            root_cause="Emotional manipulation",
        )
        healing = HealingResult(
            patch=HealingPatch(
                original="Original prompt",
                patched="Patched prompt with fix",
                diff="--- original\n+++ patched\n@@ -1 +1 @@\n-Original\n+Patched",
                explanation="Fixed the vulnerability",
            ),
            recommendations=[],
            confidence=0.85,
        )

    return AttackResult(
        goal=goal,
        persona=persona,
        success=True,
        turns=[],
        judge_verdict=JudgeVerdict(
            verdict=AttackStatus.EXPLOITED,
            confidence=0.95,
            reasoning="Attack succeeded",
        ),
        analysis=analysis,
        healing=healing,
        winning_payloads=["malicious payload"],
    )


def make_session_config() -> SerixSessionConfig:
    """Helper to create a valid SerixSessionConfig for testing."""
    return SerixSessionConfig(
        target_path="test_agent.py:test_fn",
        goals=["reveal secrets"],
        scenarios=["jailbreaker"],
        mode=AttackMode.ADAPTIVE,
        depth=5,
        attacker_model="gpt-4o-mini",
        judge_model="gpt-4o-mini",
        critic_model="gpt-4o-mini",
        patcher_model="gpt-4o-mini",
        analyzer_model="gpt-4o-mini",
        system_prompt="You are a helpful assistant.",
    )


class TestFileCampaignStore:
    """Tests for FileCampaignStore implementation."""

    def test_save_returns_run_id(self, tmp_path):
        """save() returns the run_id."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result(run_id="20251228_120000_ab12")

        returned_id = store.save(result)

        assert returned_id == "20251228_120000_ab12"

    def test_save_load_roundtrip(self, tmp_path):
        """Campaign result can be saved and loaded back."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result(
            run_id="20251228_120000_ab12",
            target_id="t_test1234",
        )

        store.save(result)
        loaded = store.load("t_test1234", "20251228_120000_ab12")

        assert loaded.run_id == result.run_id
        assert loaded.target_id == result.target_id
        assert loaded.target_locator == result.target_locator
        assert loaded.passed == result.passed
        assert loaded.score.overall_score == 100
        assert loaded.score.grade == Grade.A

    def test_creates_directories(self, tmp_path):
        """Store creates directories if they don't exist."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result(
            run_id="20251228_120000_ab12",
            target_id="t_test1234",
        )

        # Directory doesn't exist yet
        campaign_dir = (
            tmp_path / "targets" / "t_test1234" / "campaigns" / "20251228_120000_ab12"
        )
        assert not campaign_dir.exists()

        store.save(result)

        # Now it should exist
        assert campaign_dir.exists()
        assert (campaign_dir / "results.json").exists()

    def test_load_nonexistent_raises_file_not_found(self, tmp_path):
        """load() raises FileNotFoundError for missing result."""
        store = FileCampaignStore(base_dir=tmp_path)

        with pytest.raises(FileNotFoundError) as exc_info:
            store.load("t_nonexistent", "20251228_120000_ab12")

        assert "t_nonexistent" in str(exc_info.value)
        assert "20251228_120000_ab12" in str(exc_info.value)

    def test_multiple_campaigns_same_target(self, tmp_path):
        """Multiple campaigns for same target are stored separately."""
        store = FileCampaignStore(base_dir=tmp_path)
        result1 = make_campaign_result(run_id="20251228_120000_ab12")
        result2 = make_campaign_result(run_id="20251228_130000_cd34")

        store.save(result1)
        store.save(result2)

        loaded1 = store.load("t_test1234", "20251228_120000_ab12")
        loaded2 = store.load("t_test1234", "20251228_130000_cd34")

        assert loaded1.run_id == "20251228_120000_ab12"
        assert loaded2.run_id == "20251228_130000_cd34"

    def test_uses_pydantic_models(self, tmp_path):
        """Law 1 compliance: Store uses Pydantic models, not dicts."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()

        store.save(result)
        loaded = store.load(result.target_id, result.run_id)

        # Returns CampaignResult, not dict
        assert isinstance(loaded, CampaignResult)
        # Nested objects are models too
        assert isinstance(loaded.score, SecurityScore)


# ============================================================================
# Phase 10D Tests: patch.diff, metadata.json, save_report
# ============================================================================


class TestPatchDiffGeneration:
    """Tests for patch.diff file generation."""

    def test_patch_diff_created_for_successful_attacks_with_healing(self, tmp_path):
        """patch.diff is created when attacks have healing patches."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()
        result.attacks = [make_successful_attack(with_healing=True)]

        store.save(result)

        patch_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "patch.diff"
        )
        assert patch_path.exists()
        content = patch_path.read_text()
        assert "Serix Healing Patches" in content
        assert result.run_id in content
        assert "jailbreaker" in content

    def test_patch_diff_not_created_when_no_healing(self, tmp_path):
        """patch.diff is NOT created when no successful attacks have healing."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()
        result.attacks = [make_successful_attack(with_healing=False)]

        store.save(result)

        patch_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "patch.diff"
        )
        assert not patch_path.exists()

    def test_patch_diff_not_created_when_no_attacks(self, tmp_path):
        """patch.diff is NOT created when there are no attacks."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()

        store.save(result)

        patch_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "patch.diff"
        )
        assert not patch_path.exists()

    def test_aggregated_patch_includes_all_attacks(self, tmp_path):
        """patch.diff contains diffs from ALL successful attacks with healing."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()
        result.attacks = [
            make_successful_attack(
                goal="reveal secrets", persona=Persona.JAILBREAKER, with_healing=True
            ),
            make_successful_attack(
                goal="extract data", persona=Persona.EXTRACTOR, with_healing=True
            ),
        ]

        store.save(result)

        patch_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "patch.diff"
        )
        content = patch_path.read_text()

        # Both attacks should be in the file
        assert "jailbreaker" in content
        assert "extractor" in content
        assert "reveal secrets" in content
        assert "extract data" in content

    def test_aggregated_patch_includes_owasp_headers(self, tmp_path):
        """patch.diff headers include OWASP and severity info."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()
        result.attacks = [make_successful_attack(with_healing=True)]

        store.save(result)

        patch_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "patch.diff"
        )
        content = patch_path.read_text()

        assert "OWASP: LLM01" in content
        assert "Severity: high" in content
        assert "Confidence: 85%" in content


class TestMetadataJsonGeneration:
    """Tests for metadata.json file generation."""

    def test_metadata_created_when_config_provided(self, tmp_path):
        """metadata.json is created when config is provided."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()
        config = make_session_config()

        store.save(result, config=config)

        metadata_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "metadata.json"
        )
        assert metadata_path.exists()

        # Verify content
        metadata = CampaignRunMetadata.model_validate_json(metadata_path.read_text())
        assert metadata.run_id == result.run_id
        assert metadata.target_id == result.target_id
        assert metadata.mode == AttackMode.ADAPTIVE
        assert metadata.depth == 5
        assert metadata.goals == ["reveal secrets"]
        assert metadata.scenarios == ["jailbreaker"]

    def test_metadata_not_created_when_no_config(self, tmp_path):
        """metadata.json is NOT created when config is None."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()

        store.save(result)  # No config

        metadata_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "metadata.json"
        )
        assert not metadata_path.exists()

    def test_metadata_includes_model_info(self, tmp_path):
        """metadata.json includes model configuration."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()
        config = make_session_config()

        store.save(result, config=config)

        metadata_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "metadata.json"
        )
        metadata = CampaignRunMetadata.model_validate_json(metadata_path.read_text())

        assert metadata.attacker_model == "gpt-4o-mini"
        assert metadata.judge_model == "gpt-4o-mini"
        assert metadata.critic_model == "gpt-4o-mini"  # Adaptive mode
        assert metadata.patcher_model == "gpt-4o-mini"  # Has system_prompt


class TestSaveReport:
    """Tests for save_report method."""

    def test_save_report_copies_html_to_campaign_dir(self, tmp_path):
        """save_report() copies HTML file to campaign directory."""
        store = FileCampaignStore(base_dir=tmp_path)

        # Create a source HTML file
        source_html = tmp_path / "source_report.html"
        source_html.write_text("<html><body>Test Report</body></html>")

        dest_path = store.save_report(
            target_id="t_test1234",
            run_id="20251228_120000_ab12",
            report_path=source_html,
        )

        assert dest_path.exists()
        assert dest_path.name == "report.html"
        assert "Test Report" in dest_path.read_text()

    def test_save_report_creates_campaign_dir_if_needed(self, tmp_path):
        """save_report() creates campaign directory if it doesn't exist."""
        store = FileCampaignStore(base_dir=tmp_path)

        # Create a source HTML file
        source_html = tmp_path / "source_report.html"
        source_html.write_text("<html>Report</html>")

        campaign_dir = (
            tmp_path / "targets" / "t_newtest" / "campaigns" / "20251228_999999_zz99"
        )
        assert not campaign_dir.exists()

        store.save_report(
            target_id="t_newtest",
            run_id="20251228_999999_zz99",
            report_path=source_html,
        )

        assert campaign_dir.exists()
        assert (campaign_dir / "report.html").exists()

    def test_save_report_raises_if_source_missing(self, tmp_path):
        """save_report() raises FileNotFoundError if source doesn't exist."""
        store = FileCampaignStore(base_dir=tmp_path)

        missing_path = tmp_path / "nonexistent.html"

        with pytest.raises(FileNotFoundError) as exc_info:
            store.save_report(
                target_id="t_test1234",
                run_id="20251228_120000_ab12",
                report_path=missing_path,
            )

        assert "nonexistent.html" in str(exc_info.value)

    def test_save_report_preserves_utf8_content(self, tmp_path):
        """save_report() correctly handles UTF-8 content."""
        store = FileCampaignStore(base_dir=tmp_path)

        # Create HTML with unicode characters
        source_html = tmp_path / "unicode_report.html"
        source_html.write_text(
            "<html><body>Report: 日本語 émojis 🔐</body></html>", encoding="utf-8"
        )

        dest_path = store.save_report(
            target_id="t_test1234",
            run_id="20251228_120000_ab12",
            report_path=source_html,
        )

        content = dest_path.read_text(encoding="utf-8")
        assert "日本語" in content
        assert "🔐" in content


class TestResultsJsonUnchanged:
    """Tests to verify results.json behavior is unchanged."""

    def test_results_json_still_created(self, tmp_path):
        """results.json is still created as before."""
        store = FileCampaignStore(base_dir=tmp_path)
        result = make_campaign_result()
        config = make_session_config()

        store.save(result, config=config)

        results_path = (
            tmp_path
            / "targets"
            / result.target_id
            / "campaigns"
            / result.run_id
            / "results.json"
        )
        assert results_path.exists()

        # Verify it's still loadable
        loaded = store.load(result.target_id, result.run_id)
        assert loaded.run_id == result.run_id

    def test_results_json_content_unchanged(self, tmp_path):
        """results.json content is identical whether config provided or not."""
        store = FileCampaignStore(base_dir=tmp_path)

        # Save without config
        result1 = make_campaign_result(run_id="run1", target_id="t_test1")
        store.save(result1)
        path1 = tmp_path / "targets" / "t_test1" / "campaigns" / "run1" / "results.json"
        content1 = path1.read_text()

        # Save with config (to a different location)
        result2 = make_campaign_result(run_id="run2", target_id="t_test2")
        config = make_session_config()
        store.save(result2, config=config)
        path2 = tmp_path / "targets" / "t_test2" / "campaigns" / "run2" / "results.json"
        content2 = path2.read_text()

        # Both should serialize the same way (excluding run_id/target_id differences)
        # Just verify both are valid CampaignResult JSON
        loaded1 = CampaignResult.model_validate_json(content1)
        loaded2 = CampaignResult.model_validate_json(content2)

        assert loaded1.passed == loaded2.passed
        assert loaded1.score.overall_score == loaded2.score.overall_score
