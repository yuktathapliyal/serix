"""
Tests for StatusService - Phase 11B

Comprehensive tests for attack library status queries.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from serix_v2.core.contracts import (
    AttackLibrary,
    AttackStatus,
    StoredAttack,
    TargetMetadata,
    TargetType,
)
from serix_v2.services.status import StatusService

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def status_service(tmp_path: Path) -> StatusService:
    """Create StatusService with temporary base directory."""
    return StatusService(base_dir=tmp_path)


@pytest.fixture
def serix_dir(tmp_path: Path) -> Path:
    """Create .serix/targets directory structure."""
    targets_dir = tmp_path / "targets"
    targets_dir.mkdir(parents=True)
    return tmp_path


def _create_target(
    base_dir: Path,
    target_id: str,
    name: str | None = None,
    locator: str = "agent.py:my_agent",
    target_type: TargetType = TargetType.PYTHON_FUNCTION,
    attacks: list[tuple[str, AttackStatus]] | None = None,
    created_at: datetime | None = None,
) -> Path:
    """Helper to create a target directory with metadata and attacks.

    Args:
        base_dir: Base .serix directory
        target_id: Target identifier (e.g., "t_abc123")
        name: Optional alias name
        locator: Target locator string
        target_type: Type of target
        attacks: List of (strategy_id, status) tuples to create attacks
        created_at: When target was created

    Returns:
        Path to target directory
    """
    target_dir = base_dir / "targets" / target_id
    target_dir.mkdir(parents=True, exist_ok=True)

    # Create metadata
    metadata = TargetMetadata(
        target_id=target_id,
        target_type=target_type,
        locator=locator,
        name=name,
        created_at=created_at or datetime.now(timezone.utc),
    )
    (target_dir / "metadata.json").write_text(metadata.model_dump_json(indent=2))

    # Create attacks if provided
    if attacks:
        stored_attacks = []
        for i, (strategy_id, status) in enumerate(attacks):
            attack = StoredAttack(
                id=f"attack_{target_id}_{i}",
                target_id=target_id,
                goal=f"Test goal {i}",
                strategy_id=strategy_id,
                payload=f"Test payload {i}",
                status=status,
                owasp_code="LLM01",
                created_at=datetime.now(timezone.utc),
                last_tested=datetime.now(timezone.utc),
            )
            stored_attacks.append(attack)

        library = AttackLibrary(
            target_id=target_id,
            attacks=stored_attacks,
        )
        (target_dir / "attacks.json").write_text(library.model_dump_json(indent=2))

    return target_dir


# ============================================================================
# TEST: Empty/Missing State
# ============================================================================


class TestEmptyState:
    """Tests for empty or missing .serix directory."""

    def test_no_serix_dir(self, tmp_path: Path) -> None:
        """Returns empty summary when .serix doesn't exist."""
        service = StatusService(base_dir=tmp_path / "nonexistent")
        summary = service.get_all_targets()

        assert summary.total_targets == 0
        assert summary.total_attacks == 0
        assert summary.total_exploited == 0
        assert summary.total_defended == 0
        assert summary.targets == []

    def test_empty_targets_dir(self, serix_dir: Path) -> None:
        """Returns empty summary when targets/ is empty."""
        service = StatusService(base_dir=serix_dir)
        summary = service.get_all_targets()

        assert summary.total_targets == 0
        assert summary.total_attacks == 0
        assert summary.targets == []

    def test_list_target_ids_empty(self, serix_dir: Path) -> None:
        """list_target_ids returns empty list for empty targets dir."""
        service = StatusService(base_dir=serix_dir)
        ids = service.list_target_ids()
        assert ids == []

    def test_get_target_status_nonexistent(self, serix_dir: Path) -> None:
        """get_target_status returns None for nonexistent target."""
        service = StatusService(base_dir=serix_dir)
        status = service.get_target_status("t_nonexistent")
        assert status is None

    def test_get_by_name_no_targets(self, serix_dir: Path) -> None:
        """get_by_name returns None when no targets exist."""
        service = StatusService(base_dir=serix_dir)
        status = service.get_by_name("prod-agent")
        assert status is None


# ============================================================================
# TEST: Single Target
# ============================================================================


class TestSingleTarget:
    """Tests for single target scenarios."""

    def test_single_target_with_attacks(self, serix_dir: Path) -> None:
        """Correctly aggregates single target with attacks."""
        _create_target(
            serix_dir,
            "t_test123",
            name="test-agent",
            attacks=[
                ("jailbreaker", AttackStatus.EXPLOITED),
                ("extractor", AttackStatus.EXPLOITED),
                ("confuser", AttackStatus.EXPLOITED),
                ("manipulator", AttackStatus.DEFENDED),
                ("jailbreaker", AttackStatus.DEFENDED),
            ],
        )

        service = StatusService(base_dir=serix_dir)
        summary = service.get_all_targets()

        assert summary.total_targets == 1
        assert summary.total_attacks == 5
        assert summary.total_exploited == 3
        assert summary.total_defended == 2

        target = summary.targets[0]
        assert target.target_id == "t_test123"
        assert target.name == "test-agent"
        assert target.exploited == 3
        assert target.defended == 2
        assert target.health_score == 40.0  # 2/5 = 40%
        assert target.grade == "F"  # <60 = F

    def test_target_without_attacks_file(self, serix_dir: Path) -> None:
        """Handles target with metadata but no attacks.json."""
        _create_target(serix_dir, "t_new_target", name="new-agent")

        service = StatusService(base_dir=serix_dir)
        summary = service.get_all_targets()

        assert summary.total_targets == 1
        assert summary.total_attacks == 0

        target = summary.targets[0]
        assert target.total_attacks == 0
        assert target.exploited == 0
        assert target.defended == 0
        assert target.health_score == 100.0  # No attacks = healthy
        assert target.grade == "A"
        assert target.last_tested is None

    def test_target_all_defended(self, serix_dir: Path) -> None:
        """Target with all attacks defended gets A grade."""
        _create_target(
            serix_dir,
            "t_secure",
            attacks=[
                ("jailbreaker", AttackStatus.DEFENDED),
                ("extractor", AttackStatus.DEFENDED),
                ("confuser", AttackStatus.DEFENDED),
            ],
        )

        service = StatusService(base_dir=serix_dir)
        target = service.get_target_status("t_secure")

        assert target is not None
        assert target.health_score == 100.0
        assert target.grade == "A"

    def test_target_all_exploited(self, serix_dir: Path) -> None:
        """Target with all attacks exploited gets F grade."""
        _create_target(
            serix_dir,
            "t_vulnerable",
            attacks=[
                ("jailbreaker", AttackStatus.EXPLOITED),
                ("extractor", AttackStatus.EXPLOITED),
            ],
        )

        service = StatusService(base_dir=serix_dir)
        target = service.get_target_status("t_vulnerable")

        assert target is not None
        assert target.health_score == 0.0
        assert target.grade == "F"


# ============================================================================
# TEST: Multiple Targets
# ============================================================================


class TestMultipleTargets:
    """Tests for multiple target scenarios."""

    def test_multiple_targets_aggregation(self, serix_dir: Path) -> None:
        """Correctly aggregates across multiple targets."""
        _create_target(
            serix_dir,
            "t_target_a",
            name="agent-a",
            attacks=[
                ("jailbreaker", AttackStatus.EXPLOITED),
                ("extractor", AttackStatus.DEFENDED),
            ],
        )
        _create_target(
            serix_dir,
            "t_target_b",
            name="agent-b",
            attacks=[
                ("jailbreaker", AttackStatus.EXPLOITED),
                ("confuser", AttackStatus.EXPLOITED),
                ("manipulator", AttackStatus.DEFENDED),
            ],
        )

        service = StatusService(base_dir=serix_dir)
        summary = service.get_all_targets()

        assert summary.total_targets == 2
        assert summary.total_attacks == 5
        assert summary.total_exploited == 3
        assert summary.total_defended == 2

    def test_list_target_ids_multiple(self, serix_dir: Path) -> None:
        """list_target_ids returns all target IDs."""
        _create_target(serix_dir, "t_first")
        _create_target(serix_dir, "t_second")
        _create_target(serix_dir, "t_third")

        service = StatusService(base_dir=serix_dir)
        ids = service.list_target_ids()

        assert len(ids) == 3
        assert set(ids) == {"t_first", "t_second", "t_third"}


# ============================================================================
# TEST: Filtering
# ============================================================================


class TestFiltering:
    """Tests for get_by_name and get_target_status filtering."""

    def test_get_by_name_found(self, serix_dir: Path) -> None:
        """get_by_name returns correct target when name matches."""
        _create_target(serix_dir, "t_abc", name="prod-agent")
        _create_target(serix_dir, "t_def", name="staging-agent")

        service = StatusService(base_dir=serix_dir)
        target = service.get_by_name("prod-agent")

        assert target is not None
        assert target.target_id == "t_abc"
        assert target.name == "prod-agent"

    def test_get_by_name_not_found(self, serix_dir: Path) -> None:
        """get_by_name returns None when name doesn't match."""
        _create_target(serix_dir, "t_abc", name="prod-agent")

        service = StatusService(base_dir=serix_dir)
        target = service.get_by_name("nonexistent-agent")

        assert target is None

    def test_get_by_name_no_name_set(self, serix_dir: Path) -> None:
        """get_by_name skips targets without name set."""
        _create_target(serix_dir, "t_unnamed")  # No name

        service = StatusService(base_dir=serix_dir)
        target = service.get_by_name("any-name")

        assert target is None

    def test_get_target_status_found(self, serix_dir: Path) -> None:
        """get_target_status returns correct target."""
        _create_target(
            serix_dir,
            "t_specific",
            attacks=[("jailbreaker", AttackStatus.EXPLOITED)],
        )

        service = StatusService(base_dir=serix_dir)
        target = service.get_target_status("t_specific")

        assert target is not None
        assert target.target_id == "t_specific"
        assert target.total_attacks == 1


# ============================================================================
# TEST: Health Score Calculation
# ============================================================================


class TestHealthScoreCalculation:
    """Tests for health score calculation."""

    def test_health_formula(self, status_service: StatusService) -> None:
        """Health = (defended / total) * 100."""
        # Private method access for direct testing
        assert status_service._calculate_health(3, 2) == 40.0  # 2/5 = 40%
        assert status_service._calculate_health(0, 5) == 100.0  # 5/5 = 100%
        assert status_service._calculate_health(5, 0) == 0.0  # 0/5 = 0%
        assert status_service._calculate_health(0, 0) == 100.0  # No attacks = healthy

    def test_health_boundary_values(self, status_service: StatusService) -> None:
        """Test health calculation at boundary values."""
        # 90% boundary (A vs B)
        assert status_service._calculate_health(1, 9) == 90.0
        assert status_service._calculate_health(2, 8) == 80.0

        # 80% boundary (B vs C)
        assert status_service._calculate_health(2, 8) == 80.0
        assert status_service._calculate_health(3, 7) == 70.0


# ============================================================================
# TEST: Grade Calculation
# ============================================================================


class TestGradeCalculation:
    """Tests for letter grade calculation."""

    def test_grade_thresholds(self, status_service: StatusService) -> None:
        """Grade matches HTML report thresholds."""
        assert status_service._calculate_grade(100.0) == "A"
        assert status_service._calculate_grade(90.0) == "A"
        assert status_service._calculate_grade(89.9) == "B"
        assert status_service._calculate_grade(80.0) == "B"
        assert status_service._calculate_grade(79.9) == "C"
        assert status_service._calculate_grade(70.0) == "C"
        assert status_service._calculate_grade(69.9) == "D"
        assert status_service._calculate_grade(60.0) == "D"
        assert status_service._calculate_grade(59.9) == "F"
        assert status_service._calculate_grade(0.0) == "F"

    def test_grade_all_values(self, status_service: StatusService) -> None:
        """Test grade calculation for various values."""
        assert status_service._calculate_grade(95.5) == "A"
        assert status_service._calculate_grade(85.0) == "B"
        assert status_service._calculate_grade(75.0) == "C"
        assert status_service._calculate_grade(65.0) == "D"
        assert status_service._calculate_grade(50.0) == "F"
        assert status_service._calculate_grade(25.0) == "F"


# ============================================================================
# TEST: Last Tested Timestamp
# ============================================================================


class TestLastTested:
    """Tests for last_tested timestamp extraction."""

    def test_last_tested_from_attacks(self, serix_dir: Path) -> None:
        """Uses max(last_tested) from attacks.json."""
        target_dir = serix_dir / "targets" / "t_test"
        target_dir.mkdir(parents=True)

        # Create metadata
        metadata = TargetMetadata(
            target_id="t_test",
            target_type=TargetType.PYTHON_FUNCTION,
            locator="agent.py:test",
        )
        (target_dir / "metadata.json").write_text(metadata.model_dump_json())

        # Create attacks with different timestamps
        ts1 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts3 = datetime(2025, 3, 10, 12, 0, 0, tzinfo=timezone.utc)

        attacks = [
            StoredAttack(
                id="a1",
                target_id="t_test",
                goal="Goal 1",
                strategy_id="jailbreaker",
                payload="Payload 1",
                status=AttackStatus.EXPLOITED,
                last_tested=ts1,
            ),
            StoredAttack(
                id="a2",
                target_id="t_test",
                goal="Goal 2",
                strategy_id="extractor",
                payload="Payload 2",
                status=AttackStatus.DEFENDED,
                last_tested=ts2,  # This is the max
            ),
            StoredAttack(
                id="a3",
                target_id="t_test",
                goal="Goal 3",
                strategy_id="confuser",
                payload="Payload 3",
                status=AttackStatus.EXPLOITED,
                last_tested=ts3,
            ),
        ]

        library = AttackLibrary(target_id="t_test", attacks=attacks)
        (target_dir / "attacks.json").write_text(library.model_dump_json())

        service = StatusService(base_dir=serix_dir)
        target = service.get_target_status("t_test")

        assert target is not None
        assert target.last_tested == ts2  # Max timestamp

    def test_last_tested_no_attacks(self, status_service: StatusService) -> None:
        """_get_last_tested returns None for empty attacks list."""
        assert status_service._get_last_tested([]) is None


# ============================================================================
# TEST: Sorting
# ============================================================================


class TestSorting:
    """Tests for target sorting by last_tested."""

    def test_sorted_by_last_tested(self, serix_dir: Path) -> None:
        """Targets sorted by last_tested (most recent first)."""
        # Create targets with different timestamps
        ts_old = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        ts_mid = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts_new = datetime(2025, 12, 31, 12, 0, 0, tzinfo=timezone.utc)

        # Create in non-sorted order
        for target_id, ts in [
            ("t_middle", ts_mid),
            ("t_oldest", ts_old),
            ("t_newest", ts_new),
        ]:
            target_dir = serix_dir / "targets" / target_id
            target_dir.mkdir(parents=True)

            metadata = TargetMetadata(
                target_id=target_id,
                target_type=TargetType.PYTHON_FUNCTION,
                locator="agent.py:test",
            )
            (target_dir / "metadata.json").write_text(metadata.model_dump_json())

            attacks = [
                StoredAttack(
                    id=f"a_{target_id}",
                    target_id=target_id,
                    goal="Test",
                    strategy_id="jailbreaker",
                    payload="Test",
                    status=AttackStatus.EXPLOITED,
                    last_tested=ts,
                )
            ]
            library = AttackLibrary(target_id=target_id, attacks=attacks)
            (target_dir / "attacks.json").write_text(library.model_dump_json())

        service = StatusService(base_dir=serix_dir)
        summary = service.get_all_targets()

        # Should be sorted newest first
        assert len(summary.targets) == 3
        assert summary.targets[0].target_id == "t_newest"
        assert summary.targets[1].target_id == "t_middle"
        assert summary.targets[2].target_id == "t_oldest"


# ============================================================================
# TEST: Edge Cases
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_malformed_metadata_json(self, serix_dir: Path) -> None:
        """Handles malformed metadata.json gracefully."""
        target_dir = serix_dir / "targets" / "t_malformed"
        target_dir.mkdir(parents=True)

        # Write invalid JSON
        (target_dir / "metadata.json").write_text("{ invalid json }")

        service = StatusService(base_dir=serix_dir)
        summary = service.get_all_targets()

        # Should skip malformed target
        assert summary.total_targets == 0

    def test_malformed_attacks_json(self, serix_dir: Path) -> None:
        """Handles malformed attacks.json gracefully."""
        target_dir = serix_dir / "targets" / "t_bad_attacks"
        target_dir.mkdir(parents=True)

        # Valid metadata
        metadata = TargetMetadata(
            target_id="t_bad_attacks",
            target_type=TargetType.PYTHON_FUNCTION,
            locator="agent.py:test",
        )
        (target_dir / "metadata.json").write_text(metadata.model_dump_json())

        # Invalid attacks.json
        (target_dir / "attacks.json").write_text("{ invalid json }")

        service = StatusService(base_dir=serix_dir)
        target = service.get_target_status("t_bad_attacks")

        # Should still load with 0 attacks
        assert target is not None
        assert target.total_attacks == 0

    def test_non_directory_in_targets(self, serix_dir: Path) -> None:
        """Ignores files in targets/ directory."""
        targets_dir = serix_dir / "targets"

        # Create a file (not directory) in targets/
        (targets_dir / "not_a_directory.txt").write_text("some file")

        # Create a real target
        _create_target(serix_dir, "t_real")

        service = StatusService(base_dir=serix_dir)
        summary = service.get_all_targets()

        # Should only find the real target
        assert summary.total_targets == 1
        assert summary.targets[0].target_id == "t_real"

    def test_http_target_type(self, serix_dir: Path) -> None:
        """Correctly handles HTTP endpoint targets."""
        _create_target(
            serix_dir,
            "t_http",
            locator="http://localhost:8000/chat",
            target_type=TargetType.HTTP_ENDPOINT,
            attacks=[("jailbreaker", AttackStatus.EXPLOITED)],
        )

        service = StatusService(base_dir=serix_dir)
        target = service.get_target_status("t_http")

        assert target is not None
        assert target.locator == "http://localhost:8000/chat"
        assert target.target_type == "http:endpoint"


# ============================================================================
# TEST: Pydantic Models
# ============================================================================


class TestPydanticModels:
    """Tests for Pydantic model serialization."""

    def test_target_status_serialization(self, serix_dir: Path) -> None:
        """TargetStatus can be serialized to JSON."""
        _create_target(
            serix_dir,
            "t_json",
            name="json-test",
            attacks=[("jailbreaker", AttackStatus.DEFENDED)],
        )

        service = StatusService(base_dir=serix_dir)
        target = service.get_target_status("t_json")

        assert target is not None

        # Should serialize without error
        json_str = target.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["target_id"] == "t_json"
        assert parsed["name"] == "json-test"
        assert parsed["health_score"] == 100.0
        assert parsed["grade"] == "A"

    def test_status_summary_serialization(self, serix_dir: Path) -> None:
        """StatusSummary can be serialized to JSON."""
        _create_target(
            serix_dir,
            "t_sum",
            attacks=[("jailbreaker", AttackStatus.EXPLOITED)],
        )

        service = StatusService(base_dir=serix_dir)
        summary = service.get_all_targets()

        json_str = summary.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["total_targets"] == 1
        assert parsed["total_attacks"] == 1
        assert parsed["total_exploited"] == 1
        assert parsed["total_defended"] == 0
        assert len(parsed["targets"]) == 1
