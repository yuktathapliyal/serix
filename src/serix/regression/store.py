"""Persistent storage for successful attacks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from uuid import uuid4


@dataclass
class StoredAttack:
    """A successful attack stored for regression testing.

    Attributes:
        id: Unique identifier (UUID)
        timestamp: ISO format timestamp when attack was discovered
        goal: The attack goal that was achieved
        payload: The exact prompt that broke the agent
        payload_hash: SHA256 hash of payload for deduplication
        vulnerability_type: Category (jailbreak, pii_leak, injection, etc.)
        agent_response: The vulnerable response from the agent
        owasp_code: OWASP classification (LLM01, LLM02, etc.)
    """

    id: str
    timestamp: str
    goal: str
    payload: str
    payload_hash: str
    vulnerability_type: str
    agent_response: str
    owasp_code: str

    @classmethod
    def create(
        cls,
        goal: str,
        payload: str,
        vulnerability_type: str,
        agent_response: str,
        owasp_code: str = "LLM01",
    ) -> "StoredAttack":
        """Create a new StoredAttack with auto-generated id, timestamp, and hash.

        Returns:
            StoredAttack instance ready for storage
        """
        return cls(
            id=str(uuid4())[:8],
            timestamp=datetime.now().isoformat(),
            goal=goal,
            payload=payload,
            payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
            vulnerability_type=vulnerability_type,
            agent_response=agent_response,
            owasp_code=owasp_code,
        )


class AttackStore:
    """Stores attacks in .serix/attacks.json with auto-dedup and pruning."""

    def __init__(self, path: Path | None = None):
        self.path = path or Path(".serix/attacks.json")

    def _ensure_dir(self) -> None:
        """Ensure the .serix directory exists."""
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, attack: StoredAttack) -> bool:
        """Save attack to storage.

        Returns:
            True if saved, False if duplicate (by payload hash)
        """
        self._ensure_dir()

        existing = self.load_all()

        # Check for duplicate payload
        existing_hashes = {a.payload_hash for a in existing}
        if attack.payload_hash in existing_hashes:
            return False

        existing.append(attack)

        # Prune old attacks per type
        existing = self._prune_old(existing)

        self._write(existing)
        return True

    def load_all(self) -> list[StoredAttack]:
        """Load all stored attacks.

        Returns:
            List of all attacks, empty if none exist
        """
        if not self.path.exists():
            return []

        try:
            with open(self.path) as f:
                data = json.load(f)
            return [StoredAttack(**item) for item in data]
        except (json.JSONDecodeError, KeyError, TypeError):
            return []

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

        # Keep latest N per type (sorted by timestamp)
        result: list[StoredAttack] = []
        for vuln_type, type_attacks in by_type.items():
            sorted_attacks = sorted(
                type_attacks, key=lambda a: a.timestamp, reverse=True
            )
            result.extend(sorted_attacks[:max_per_type])

        return result

    @staticmethod
    def hash_payload(payload: str) -> str:
        """SHA256 hash for deduplication."""
        return hashlib.sha256(payload.encode()).hexdigest()
