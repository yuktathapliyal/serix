"""
Serix v2 - Status Query Service

Provides aggregated statistics across all tested targets.
Used by: serix status CLI command (Phase 12A)

Law Compliance:
- Law 1: Pydantic models for all returns
- Law 2: No typer/rich/click imports
- Law 4: No module-level globals

Reference: Phase 11B, Spec 2.4
"""

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from serix_v2.core.constants import APP_DIR
from serix_v2.core.contracts import AttackLibrary, AttackStatus, TargetMetadata


class TargetStatus(BaseModel):
    """Status for a single target."""

    target_id: str
    name: str | None = None  # User alias from metadata
    locator: str  # file.py:func or http://...
    target_type: str  # python:function, python:class, http
    total_attacks: int
    exploited: int
    defended: int
    health_score: float  # 0-100, (defended/total) * 100
    grade: str  # A-F letter grade (matches HTML report)
    last_tested: datetime | None
    created_at: datetime


class StatusSummary(BaseModel):
    """Aggregate status across all targets."""

    total_targets: int
    total_attacks: int
    total_exploited: int
    total_defended: int
    targets: list[TargetStatus]


class StatusService:
    """Query attack library status across all targets.

    Usage:
        service = StatusService()
        summary = service.get_all_targets()

        # Or filter:
        target = service.get_by_name("prod-agent")
        target = service.get_target_status("t_4f92c1a8")
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        """Initialize with storage directory.

        Args:
            base_dir: Path to .serix directory. Defaults to .serix/
        """
        self._base_dir = base_dir or Path(APP_DIR)

    def get_all_targets(self) -> StatusSummary:
        """Get status for all tested targets.

        Returns:
            StatusSummary with aggregate counts and per-target breakdown
        """
        targets_dir = self._base_dir / "targets"
        if not targets_dir.exists():
            return StatusSummary(
                total_targets=0,
                total_attacks=0,
                total_exploited=0,
                total_defended=0,
                targets=[],
            )

        targets: list[TargetStatus] = []
        for target_dir in targets_dir.iterdir():
            if not target_dir.is_dir():
                continue
            target_id = target_dir.name
            status = self._load_target_status(target_id, target_dir)
            if status:
                targets.append(status)

        # Sort by last_tested (most recent first)
        targets.sort(key=lambda t: t.last_tested or datetime.min, reverse=True)

        return StatusSummary(
            total_targets=len(targets),
            total_attacks=sum(t.total_attacks for t in targets),
            total_exploited=sum(t.exploited for t in targets),
            total_defended=sum(t.defended for t in targets),
            targets=targets,
        )

    def get_target_status(self, target_id: str) -> TargetStatus | None:
        """Get status for a specific target by ID.

        Args:
            target_id: Target identifier (e.g., "t_4f92c1a8")

        Returns:
            TargetStatus if found, None otherwise
        """
        target_dir = self._base_dir / "targets" / target_id
        if not target_dir.exists():
            return None
        return self._load_target_status(target_id, target_dir)

    def get_by_name(self, name: str) -> TargetStatus | None:
        """Get status by target alias name.

        Args:
            name: User-provided alias from --name flag

        Returns:
            TargetStatus if found, None otherwise
        """
        targets_dir = self._base_dir / "targets"
        if not targets_dir.exists():
            return None

        for target_dir in targets_dir.iterdir():
            if not target_dir.is_dir():
                continue
            metadata_path = target_dir / "metadata.json"
            if metadata_path.exists():
                try:
                    metadata = TargetMetadata.model_validate_json(
                        metadata_path.read_text()
                    )
                    if metadata.name == name:
                        return self._load_target_status(target_dir.name, target_dir)
                except Exception:
                    # Skip malformed metadata files
                    continue
        return None

    def list_target_ids(self) -> list[str]:
        """List all target IDs in the attack library.

        Returns:
            List of target_id strings
        """
        targets_dir = self._base_dir / "targets"
        if not targets_dir.exists():
            return []

        return [
            target_dir.name
            for target_dir in targets_dir.iterdir()
            if target_dir.is_dir()
        ]

    def _load_target_status(
        self, target_id: str, target_dir: Path
    ) -> TargetStatus | None:
        """Load status for a single target from disk.

        Args:
            target_id: Target identifier
            target_dir: Path to target directory

        Returns:
            TargetStatus if metadata exists, None otherwise
        """
        metadata_path = target_dir / "metadata.json"
        attacks_path = target_dir / "attacks.json"

        # Metadata is required
        if not metadata_path.exists():
            return None

        try:
            metadata = TargetMetadata.model_validate_json(metadata_path.read_text())
        except Exception:
            return None

        # Load attacks (optional - target may exist without attacks)
        attacks: list = []
        if attacks_path.exists():
            try:
                library = AttackLibrary.model_validate_json(attacks_path.read_text())
                attacks = library.attacks
            except Exception:
                pass

        # Count by status
        exploited = sum(1 for a in attacks if a.status == AttackStatus.EXPLOITED)
        defended = sum(1 for a in attacks if a.status == AttackStatus.DEFENDED)
        total = exploited + defended

        # Calculate health and grade
        health_score = self._calculate_health(exploited, defended)
        grade = self._calculate_grade(health_score)

        # Get last tested timestamp
        last_tested = self._get_last_tested(attacks)

        return TargetStatus(
            target_id=target_id,
            name=metadata.name,
            locator=metadata.locator,
            target_type=metadata.target_type.value,
            total_attacks=total,
            exploited=exploited,
            defended=defended,
            health_score=health_score,
            grade=grade,
            last_tested=last_tested,
            created_at=metadata.created_at,
        )

    def _calculate_health(self, exploited: int, defended: int) -> float:
        """Calculate health score as percentage of defended attacks.

        Health = (defended / total) * 100
        - 95-100%: Excellent (green)
        - 80-95%: Good (yellow)
        - 0-80%: Needs work (red)

        Args:
            exploited: Number of exploited attacks
            defended: Number of defended attacks

        Returns:
            Health score 0-100
        """
        total = exploited + defended
        if total == 0:
            return 100.0  # No attacks = healthy
        return (defended / total) * 100.0

    def _calculate_grade(self, health_score: float) -> str:
        """Calculate letter grade from health score.

        Uses same mapping as HTML report for consistency:
        - 90+: A
        - 80+: B
        - 70+: C
        - 60+: D
        - <60: F

        Args:
            health_score: Health percentage 0-100

        Returns:
            Letter grade A-F
        """
        if health_score >= 90:
            return "A"
        elif health_score >= 80:
            return "B"
        elif health_score >= 70:
            return "C"
        elif health_score >= 60:
            return "D"
        else:
            return "F"

    def _get_last_tested(self, attacks: list) -> datetime | None:
        """Get most recent test timestamp from attacks.json.

        PERFORMANCE NOTE: We use attacks.json as the ONLY source for last_tested.
        Every test run (attack + regression) updates the last_tested field in the
        attack library, so this file always has the most up-to-date timestamp.

        We do NOT scan campaigns/ directories because:
        - A target tested 1000 times = 1000 results.json files to read
        - That would make `serix status` feel sluggish
        - attacks.json already has all the info we need

        Args:
            attacks: List of StoredAttack from attacks.json

        Returns:
            Most recent last_tested datetime, or None if no attacks
        """
        if not attacks:
            return None

        # Use max(last_tested) from attacks - fast O(n) scan of in-memory list
        timestamps = [a.last_tested for a in attacks if a.last_tested]
        return max(timestamps) if timestamps else None
