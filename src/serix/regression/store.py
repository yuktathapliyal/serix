"""Persistent storage for successful attacks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from uuid import uuid4


def get_serix_version() -> str:
    """Get Serix version dynamically from package metadata.

    Falls back to 'dev' if running from source without install.
    """
    try:
        return version("serix")
    except PackageNotFoundError:
        return "dev"


@dataclass
class StoredAttack:
    """A stored attack for regression testing.

    Tracks attacks discovered during testing and their current status.
    Status can change as the agent is patched and re-tested.

    Attributes:
        id: Unique identifier (UUID)
        payload: The exact prompt used in the attack
        payload_hash: SHA256 hash of payload for deduplication
        goal: The attack goal that was attempted
        vulnerability_type: Category (jailbreak, pii_leak, injection, etc.)
        owasp_code: OWASP classification (LLM01, LLM02, etc.)
        first_exploited_at: ISO timestamp when attack first succeeded
        last_verified_at: ISO timestamp of last Immune Check
        current_status: 'exploited' or 'defended'
        judge_reasoning: Latest reasoning from judge LLM
        agent_response: The agent's response to the attack
        strategy_id: Attack strategy identifier for deduplication (e.g., 'grandma_exploit')
        attacker_model: LLM model used for generating attacks
        judge_model: LLM model used for judging attack success
        critic_model: LLM model used for critic feedback (if any)
        config_snapshot: Test configuration at time of attack (depth, mode, fuzz_settings)
        serix_version: Version of Serix that ran the test
        test_duration_seconds: Total time spent running the test
    """

    id: str
    payload: str
    payload_hash: str
    goal: str
    vulnerability_type: str
    owasp_code: str
    first_exploited_at: str
    last_verified_at: str
    current_status: str  # 'exploited' or 'defended'
    judge_reasoning: str
    agent_response: str
    # v0.2.5 fields
    strategy_id: str = "unknown"
    # v0.2.6 metadata fields
    attacker_model: str = "unknown"
    judge_model: str = "unknown"
    critic_model: str = "unknown"
    config_snapshot: dict[str, Any] = field(default_factory=dict)
    serix_version: str = "unknown"
    test_duration_seconds: float = 0.0

    @classmethod
    def create(
        cls,
        goal: str,
        payload: str,
        vulnerability_type: str,
        agent_response: str,
        owasp_code: str = "LLM01",
        judge_reasoning: str = "",
        strategy_id: str = "unknown",
        # v0.2.6 metadata parameters
        attacker_model: str = "unknown",
        judge_model: str = "unknown",
        critic_model: str = "unknown",
        config_snapshot: dict[str, Any] | None = None,
        serix_version: str | None = None,
        test_duration_seconds: float = 0.0,
    ) -> "StoredAttack":
        """Create a new StoredAttack with auto-generated id and timestamps.

        Args:
            goal: The attack goal that was attempted
            payload: The exact prompt used in the attack
            vulnerability_type: Category (jailbreak, pii_leak, etc.)
            agent_response: The agent's response to the attack
            owasp_code: OWASP classification (default: LLM01)
            judge_reasoning: Latest reasoning from judge LLM
            strategy_id: Attack strategy for deduplication (e.g., 'grandma_exploit')
            attacker_model: LLM model used for generating attacks
            judge_model: LLM model used for judging attack success
            critic_model: LLM model used for critic feedback
            config_snapshot: Test configuration (depth, mode, fuzz_settings)
            serix_version: Version of Serix (auto-detected if None)
            test_duration_seconds: Total test duration in seconds

        Returns:
            StoredAttack instance ready for storage
        """
        now = datetime.now().isoformat()
        return cls(
            id=str(uuid4())[:8],
            payload=payload,
            payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
            goal=goal,
            vulnerability_type=vulnerability_type,
            owasp_code=owasp_code,
            first_exploited_at=now,
            last_verified_at=now,
            current_status="exploited",
            judge_reasoning=judge_reasoning,
            agent_response=agent_response,
            strategy_id=strategy_id,
            # v0.2.6 metadata
            attacker_model=attacker_model,
            judge_model=judge_model,
            critic_model=critic_model,
            config_snapshot=config_snapshot or {},
            serix_version=serix_version or get_serix_version(),
            test_duration_seconds=test_duration_seconds,
        )


class AttackStore:
    """Stores attacks in .serix/attacks.json with auto-dedup and pruning."""

    def __init__(self, path: Path | None = None):
        self.path = path or Path(".serix/attacks.json")

    def _ensure_dir(self) -> None:
        """Ensure the .serix directory exists."""
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, attack: StoredAttack) -> bool:
        """Save attack to storage with upsert by (goal, strategy_id).

        Deduplication uses (goal, strategy_id) composite key:
        - Same goal + same strategy = overwrite (fixes LLM jitter)
        - Different goal + same strategy = keep both (different security context)

        Returns:
            True if saved (new or updated), False should not happen with upsert
        """
        self._ensure_dir()

        existing = self.load_all()

        # Find existing attack with same (goal, strategy_id) - upsert logic
        existing_index = next(
            (
                i
                for i, a in enumerate(existing)
                if a.goal == attack.goal and a.strategy_id == attack.strategy_id
            ),
            None,
        )

        if existing_index is not None:
            # Overwrite existing record (fixes jitter duplicates)
            existing[existing_index] = attack
        else:
            # New (goal, strategy_id) combination
            existing.append(attack)

        # Prune old attacks per type
        existing = self._prune_old(existing)

        self._write(existing)
        return True

    def load_all(self, skip_mitigated: bool = False) -> list[StoredAttack]:
        """Load all stored attacks with automatic schema migration.

        Migrates legacy attacks through the migration chain:
        - v0.2.0 → v0.2.5: timestamp → first_exploited_at, adds current_status
        - v0.2.5 → v0.2.6: adds attacker_model, judge_model, config_snapshot, etc.

        Args:
            skip_mitigated: If True, only return attacks with status 'exploited'

        Returns:
            List of all attacks, empty if none exist
        """
        if not self.path.exists():
            return []

        try:
            with open(self.path) as f:
                data = json.load(f)

            attacks = []
            needs_migration = False

            for item in data:
                # Skip non-dict items (malformed data)
                if not isinstance(item, dict):
                    continue

                # Migration chain: v0.2.0 → v0.2.5 → v0.2.6

                # Step 1: v0.2.0 → v0.2.5 (legacy timestamp migration)
                if "timestamp" in item and "first_exploited_at" not in item:
                    needs_migration = True
                    item = self._migrate_legacy(item)

                # Step 2: v0.2.5 → v0.2.6 (metadata fields)
                if "serix_version" not in item:
                    needs_migration = True
                    item = self._migrate_v025_to_v026(item)

                attacks.append(StoredAttack(**item))

            # Write migrated data back if we updated any records
            if needs_migration:
                self._write(attacks)

            # Filter if skip_mitigated requested
            if skip_mitigated:
                attacks = [a for a in attacks if a.current_status == "exploited"]

            return attacks
        except (json.JSONDecodeError, KeyError, TypeError):
            return []

    def _migrate_legacy(self, item: dict) -> dict:
        """Migrate a v0.2.0 attack record to current schema.

        Handles the full migration from v0.2.0 → current (v0.2.6+).
        """
        timestamp = item.pop("timestamp", datetime.now().isoformat())
        return {
            # v0.2.0 → v0.2.5 fields
            "id": item.get("id", str(uuid4())[:8]),
            "payload": item.get("payload", ""),
            "payload_hash": item.get("payload_hash", ""),
            "goal": item.get("goal", ""),
            "vulnerability_type": item.get("vulnerability_type", "unknown"),
            "owasp_code": item.get("owasp_code", "LLM01"),
            "first_exploited_at": timestamp,
            "last_verified_at": timestamp,
            "current_status": "exploited",  # Assume exploited for legacy
            "judge_reasoning": "",
            "agent_response": item.get("agent_response", ""),
            "strategy_id": item.get("strategy_id", "unknown"),
            # v0.2.6 metadata fields
            "attacker_model": item.get("attacker_model", "unknown"),
            "judge_model": item.get("judge_model", "unknown"),
            "critic_model": item.get("critic_model", "unknown"),
            "config_snapshot": item.get("config_snapshot", {}),
            "serix_version": "pre-0.2.6",  # Mark as legacy
            "test_duration_seconds": item.get("test_duration_seconds", 0.0),
        }

    def _migrate_v025_to_v026(self, item: dict) -> dict:
        """Migrate a v0.2.5 attack record to v0.2.6 schema.

        Adds the new metadata fields introduced in v0.2.6.
        Preserves all existing v0.2.5 fields.
        """
        # Add new v0.2.6 fields with defaults
        item.setdefault("attacker_model", "unknown")
        item.setdefault("judge_model", "unknown")
        item.setdefault("critic_model", "unknown")
        item.setdefault("config_snapshot", {})
        item.setdefault("serix_version", "pre-0.2.6")
        item.setdefault("test_duration_seconds", 0.0)
        return item

    def load_by_type(self, vuln_type: str) -> list[StoredAttack]:
        """Load attacks filtered by vulnerability type.

        Returns:
            List of attacks matching the specified type
        """
        return [a for a in self.load_all() if a.vulnerability_type == vuln_type]

    def count(self) -> int:
        """Get the number of stored attacks.

        Returns:
            Total count of attacks in storage
        """
        return len(self.load_all())

    def clear(self) -> None:
        """Clear all stored attacks."""
        if self.path.exists():
            self.path.unlink()

    def _write(self, attacks: list[StoredAttack]) -> None:
        """Write attacks to file."""
        self._ensure_dir()
        with open(self.path, "w") as f:
            json.dump([asdict(a) for a in attacks], f, indent=2)

    def update(self, attack: StoredAttack) -> None:
        """Update an attack in-place by ID.

        Used to update status after Immune Check.
        """
        attacks = self.load_all()
        for i, a in enumerate(attacks):
            if a.id == attack.id:
                attacks[i] = attack
                break
        self._write(attacks)

    def _prune_old(
        self, attacks: list[StoredAttack], max_per_type: int = 100
    ) -> list[StoredAttack]:
        """Keep only latest N attacks per type."""
        # Group by type
        by_type: dict[str, list[StoredAttack]] = {}
        for attack in attacks:
            if attack.vulnerability_type not in by_type:
                by_type[attack.vulnerability_type] = []
            by_type[attack.vulnerability_type].append(attack)

        # Keep latest N per type (sorted by first_exploited_at)
        result: list[StoredAttack] = []
        for vuln_type, type_attacks in by_type.items():
            sorted_attacks = sorted(
                type_attacks, key=lambda a: a.first_exploited_at, reverse=True
            )
            result.extend(sorted_attacks[:max_per_type])

        return result

    @staticmethod
    def hash_payload(payload: str) -> str:
        """SHA256 hash for deduplication."""
        return hashlib.sha256(payload.encode()).hexdigest()
