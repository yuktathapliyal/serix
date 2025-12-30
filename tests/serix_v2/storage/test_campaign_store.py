"""
Tests for FileCampaignStore.

Phase 3A-T04: Storage layer tests.
"""

import pytest

from serix_v2.core.contracts import CampaignResult, Grade, SecurityScore, TargetType
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
