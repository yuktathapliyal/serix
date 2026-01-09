"""
Serix v2 - Directory Structure Tests

Phase 7.5: 8 tests verifying storage paths follow spec exactly.

Directory structure:
    .serix/
    ├── index.json                    # Alias -> target_id mapping
    └── targets/
        └── {target_id}/
            ├── attacks.json          # Attack library
            ├── metadata.json         # Target metadata
            └── campaigns/
                └── {run_id}/
                    └── results.json  # Campaign results

Reference: docs/serix-phoenix-rebuild/build-plans/PHASE-7-COMPREHENSIVE-TESTS-2025-12-30.md
"""

import re
from pathlib import Path

from serix_v2.core.contracts import (
    AttackLibrary,
    AttackStatus,
    CampaignResult,
    Grade,
    SecurityScore,
    StoredAttack,
    TargetIndex,
    TargetMetadata,
    TargetType,
)
from serix_v2.core.id_gen import generate_attack_id, generate_run_id, generate_target_id
from serix_v2.storage import FileAttackStore, FileCampaignStore


class TestDirectoryStructure:
    """Tests for spec-compliant directory structure."""

    def test_serix_dir_created_on_first_write(self, tmp_path: Path) -> None:
        """Base .serix directory created on first write."""
        base_dir = tmp_path / ".serix"
        assert not base_dir.exists()

        # Create attack store and save
        store = FileAttackStore(base_dir=base_dir)
        library = AttackLibrary(target_id="t_test1234", attacks=[])
        store.save(library)

        assert base_dir.exists()
        assert base_dir.is_dir()

    def test_target_dir_follows_pattern(self, tmp_path: Path) -> None:
        """Target directory follows pattern: targets/{target_id}/"""
        base_dir = tmp_path / ".serix"
        target_id = "t_abc12345"

        store = FileAttackStore(base_dir=base_dir)
        library = AttackLibrary(target_id=target_id, attacks=[])
        store.save(library)

        target_dir = base_dir / "targets" / target_id
        assert target_dir.exists()
        assert target_dir.is_dir()

    def test_attacks_json_location(self, tmp_path: Path) -> None:
        """Attack library stored at targets/{target_id}/attacks.json"""
        base_dir = tmp_path / ".serix"
        target_id = "t_attacks123"

        store = FileAttackStore(base_dir=base_dir)

        # Add an attack
        attack = StoredAttack(
            id=generate_attack_id(),
            target_id=target_id,
            goal="test goal",
            strategy_id="jailbreaker",
            payload="test payload",
            status=AttackStatus.EXPLOITED,
        )
        store.add_attack(attack)

        # Verify file location
        attacks_file = base_dir / "targets" / target_id / "attacks.json"
        assert attacks_file.exists()
        assert attacks_file.is_file()

        # Verify content is valid JSON
        library = AttackLibrary.model_validate_json(attacks_file.read_text())
        assert library.target_id == target_id
        assert len(library.attacks) == 1

    def test_campaign_results_location(self, tmp_path: Path) -> None:
        """Campaign results at targets/{target_id}/campaigns/{run_id}/results.json"""
        base_dir = tmp_path / ".serix"
        target_id = "t_campaign123"
        run_id = generate_run_id()

        store = FileCampaignStore(base_dir=base_dir)

        result = CampaignResult(
            run_id=run_id,
            target_id=target_id,
            target_locator="test.py:fn",
            target_type=TargetType.PYTHON_FUNCTION,
            passed=True,
            score=SecurityScore(overall_score=100, grade=Grade.A),
        )
        store.save(result)

        # Verify file location
        results_file = (
            base_dir / "targets" / target_id / "campaigns" / run_id / "results.json"
        )
        assert results_file.exists()
        assert results_file.is_file()

        # Verify content is valid JSON
        loaded = CampaignResult.model_validate_json(results_file.read_text())
        assert loaded.run_id == run_id
        assert loaded.target_id == target_id

    def test_index_json_created_with_alias(self, tmp_path: Path) -> None:
        """Index file at .serix/index.json stores alias -> target_id mapping."""
        base_dir = tmp_path / ".serix"
        index_path = base_dir / "index.json"

        # Create index manually (workflow creates this)
        base_dir.mkdir(parents=True, exist_ok=True)

        index = TargetIndex()
        index.aliases["my-agent"] = "t_abc12345"
        index.aliases["other-agent"] = "t_def67890"

        index_path.write_text(index.model_dump_json(indent=2))

        # Verify location and content
        assert index_path.exists()
        loaded = TargetIndex.model_validate_json(index_path.read_text())
        assert loaded.aliases["my-agent"] == "t_abc12345"
        assert loaded.aliases["other-agent"] == "t_def67890"

    def test_metadata_json_created(self, tmp_path: Path) -> None:
        """Metadata file at targets/{target_id}/metadata.json stores target info."""
        base_dir = tmp_path / ".serix"
        target_id = "t_meta123"
        target_dir = base_dir / "targets" / target_id
        metadata_path = target_dir / "metadata.json"

        # Create metadata (workflow creates this)
        target_dir.mkdir(parents=True, exist_ok=True)

        metadata = TargetMetadata(
            target_id=target_id,
            target_type=TargetType.PYTHON_FUNCTION,
            locator="src/agent.py:my_agent",
            name="my-agent",
        )

        metadata_path.write_text(metadata.model_dump_json(indent=2))

        # Verify location and content
        assert metadata_path.exists()
        loaded = TargetMetadata.model_validate_json(metadata_path.read_text())
        assert loaded.target_id == target_id
        assert loaded.locator == "src/agent.py:my_agent"
        assert loaded.name == "my-agent"

    def test_run_id_format(self, tmp_path: Path) -> None:
        """Run ID follows format: YYYYMMDD_HHMMSS_XXXX"""
        # Pattern: 8 digits, underscore, 6 digits, underscore, 4 hex chars
        pattern = re.compile(r"^\d{8}_\d{6}_[a-f0-9]{4}$")

        # Generate multiple run IDs and verify format
        for _ in range(10):
            run_id = generate_run_id()
            assert pattern.match(run_id), f"Run ID doesn't match pattern: {run_id}"

    def test_target_id_format(self, tmp_path: Path) -> None:
        """Target ID follows format: t_XXXXXXXX (t_ prefix + 8 hex chars)"""
        # Pattern: t_ prefix followed by 8 hex chars
        pattern = re.compile(r"^t_[a-f0-9]{8}$")

        # Test auto-generated IDs
        test_cases = [
            "agent.py:my_agent",
            "src/lib/agent.py:process",
            "http://localhost:8000/chat",
        ]

        for locator in test_cases:
            target_id = generate_target_id(locator=locator)
            assert pattern.match(
                target_id
            ), f"Target ID doesn't match pattern: {target_id}"

        # Test with name
        target_id = generate_target_id(locator="test.py:fn", name="my-custom-name")
        assert pattern.match(target_id)


class TestDirectoryIsolation:
    """Tests for target isolation in storage."""

    def test_multiple_targets_separate_directories(self, tmp_path: Path) -> None:
        """Each target has its own isolated directory."""
        base_dir = tmp_path / ".serix"
        store = FileAttackStore(base_dir=base_dir)

        targets = ["t_target001", "t_target002", "t_target003"]

        # Create libraries for each target
        for target_id in targets:
            library = AttackLibrary(
                target_id=target_id,
                attacks=[
                    StoredAttack(
                        id=generate_attack_id(),
                        target_id=target_id,
                        goal=f"goal for {target_id}",
                        strategy_id="jailbreaker",
                        payload="test",
                        status=AttackStatus.EXPLOITED,
                    )
                ],
            )
            store.save(library)

        # Verify each target has its own directory
        for target_id in targets:
            target_dir = base_dir / "targets" / target_id
            assert target_dir.exists()
            attacks_file = target_dir / "attacks.json"
            assert attacks_file.exists()

            # Verify content is isolated
            library = store.load(target_id)
            assert library.target_id == target_id
            assert library.attacks[0].goal == f"goal for {target_id}"

    def test_multiple_campaigns_per_target(self, tmp_path: Path) -> None:
        """Each campaign has its own run_id directory under target."""
        base_dir = tmp_path / ".serix"
        store = FileCampaignStore(base_dir=base_dir)

        target_id = "t_multicampaign"
        run_ids = [generate_run_id() for _ in range(3)]

        # Save multiple campaigns
        for i, run_id in enumerate(run_ids):
            result = CampaignResult(
                run_id=run_id,
                target_id=target_id,
                target_locator="test.py:fn",
                target_type=TargetType.PYTHON_FUNCTION,
                passed=i % 2 == 0,  # Alternate pass/fail
                score=SecurityScore(overall_score=100 - i * 10, grade=Grade.A),
            )
            store.save(result)

        # Verify each campaign has its own directory
        campaigns_dir = base_dir / "targets" / target_id / "campaigns"
        assert campaigns_dir.exists()

        for run_id in run_ids:
            run_dir = campaigns_dir / run_id
            assert run_dir.exists()
            results_file = run_dir / "results.json"
            assert results_file.exists()

            # Verify content is correct
            loaded = store.load(target_id, run_id)
            assert loaded.run_id == run_id
