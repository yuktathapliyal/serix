"""
Serix v2 - Attack Store Implementation

Implements the AttackStore protocol for persisting attack libraries.

Storage path: {base_dir}/targets/{target_id}/attacks.json

Reference: Phase 3A, Spec 1.15
"""

from datetime import datetime, timezone
from pathlib import Path

from serix_v2.core.constants import APP_DIR
from serix_v2.core.contracts import AttackLibrary, StoredAttack


class FileAttackStore:
    """
    File-based implementation of the AttackStore protocol.

    Stores attack libraries as JSON files at:
    {base_dir}/targets/{target_id}/attacks.json
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        """
        Initialize the attack store.

        Args:
            base_dir: Base directory for storage. Defaults to ".serix"
        """
        self._base_dir = base_dir or Path(APP_DIR)

    def _get_library_path(self, target_id: str) -> Path:
        """Get the path to the attack library file for a target."""
        return self._base_dir / "targets" / target_id / "attacks.json"

    def load(self, target_id: str) -> AttackLibrary:
        """
        Load attack library for a target.

        Returns empty library if file doesn't exist.
        """
        path = self._get_library_path(target_id)

        if not path.exists():
            return AttackLibrary(target_id=target_id, attacks=[])

        return AttackLibrary.model_validate_json(path.read_text())

    def save(self, library: AttackLibrary) -> None:
        """
        Save attack library to disk.

        Creates directories if they don't exist.
        """
        path = self._get_library_path(library.target_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(library.model_dump_json(indent=2))

    def add_attack(self, attack: StoredAttack) -> None:
        """
        Add or update an attack in the library.

        Dedup key: (goal, strategy_id)
        - If attack with same key exists, update it (refresh last_tested)
        - Otherwise, append as new attack
        """
        library = self.load(attack.target_id)

        # Build dict for fast O(1) lookup: (goal, strategy_id) -> index
        existing: dict[tuple[str, str], int] = {
            (a.goal, a.strategy_id): i for i, a in enumerate(library.attacks)
        }

        key = (attack.goal, attack.strategy_id)

        if key in existing:
            # Update existing attack (always refresh last_tested)
            updated_attack = attack.model_copy(
                update={"last_tested": datetime.now(timezone.utc)}
            )
            library.attacks[existing[key]] = updated_attack
        else:
            # Append new attack
            library.attacks.append(attack)

        self.save(library)
