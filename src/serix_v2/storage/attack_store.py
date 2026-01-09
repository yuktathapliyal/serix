"""
Serix v2 - Attack Store Implementation

Implements the AttackStore protocol for persisting attack libraries.

Storage path: {base_dir}/targets/{target_id}/attacks.json

Reference: Phase 3A, Spec 1.15
"""

from datetime import datetime, timezone
from pathlib import Path

from serix_v2.core.constants import APP_DIR
from serix_v2.core.contracts import AttackLibrary, AttackStatus, StoredAttack


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

        Phase 12O: Implements streak reset logic for exploited_since.
        """
        library = self.load(attack.target_id)

        # Build dict for fast O(1) lookup: (goal, strategy_id) -> index
        existing: dict[tuple[str, str], int] = {
            (a.goal, a.strategy_id): i for i, a in enumerate(library.attacks)
        }

        key = (attack.goal, attack.strategy_id)

        if key in existing:
            # Update existing attack
            idx = existing[key]
            old_attack = library.attacks[idx]

            # Streak reset logic for updates
            if (
                old_attack.status == AttackStatus.DEFENDED
                and attack.status == AttackStatus.EXPLOITED
            ):
                # Re-introduced: reset streak to now
                exploited_since = datetime.now(timezone.utc)
            elif (
                old_attack.status == AttackStatus.EXPLOITED
                and attack.status == AttackStatus.DEFENDED
            ):
                # Fixed: clear streak
                exploited_since = None
            else:
                # No change: keep existing streak
                exploited_since = old_attack.exploited_since

            updated_attack = attack.model_copy(
                update={
                    "last_tested": datetime.now(timezone.utc),
                    "exploited_since": exploited_since,
                }
            )
            library.attacks[idx] = updated_attack
        else:
            # NEW attack - initialize exploited_since if exploited
            if (
                attack.status == AttackStatus.EXPLOITED
                and attack.exploited_since is None
            ):
                attack = attack.model_copy(
                    update={"exploited_since": attack.created_at}
                )
            library.attacks.append(attack)

        self.save(library)
