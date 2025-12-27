"""Storage service for .serix/ persistence.

Manages the attack library and target metadata stored in the .serix/
directory. Uses atomic writes to prevent file corruption.

Directory structure:
    .serix/
    ├── index.json           # Alias -> target_id mapping
    └── targets/
        └── <target_id>/
            ├── metadata.json     # TargetMetadata
            ├── attacks.json      # AttackLibrary
            └── campaigns/        # Campaign results (Sprint 3)
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.constants import (
    APP_DIR,
    ATTACKS_FILENAME,
    INDEX_FILENAME,
    METADATA_FILENAME,
    TARGETS_DIR,
)
from ..core.errors import StorageError
from ..core.types import (
    AttackLibrary,
    AttackResult,
    IndexFile,
    StoredAttack,
    TargetMetadata,
)

if TYPE_CHECKING:
    pass


class StorageService:
    """Service for persisting attack data to .serix/.

    Provides methods for:
    - Initializing the .serix/ directory structure
    - Managing the index (alias -> target_id mapping)
    - Storing and loading target metadata
    - Storing and loading attack libraries
    - Adding attacks with deduplication

    All writes are atomic (temp file + os.replace) to prevent
    file corruption if the process is interrupted.
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        """Initialize storage service.

        Args:
            base_dir: Base directory for .serix/ (default: current dir)
        """
        self._base = (base_dir or Path.cwd()) / APP_DIR
        self._index_path = self._base / INDEX_FILENAME
        self._targets_dir = self._base / TARGETS_DIR

    @property
    def base_dir(self) -> Path:
        """Get the .serix/ directory path."""
        return self._base

    def initialize(self) -> None:
        """Create .serix/ directory structure if it doesn't exist."""
        self._base.mkdir(exist_ok=True)
        self._targets_dir.mkdir(exist_ok=True)
        if not self._index_path.exists():
            self._write_index(IndexFile())

    def exists(self) -> bool:
        """Check if .serix/ directory exists."""
        return self._base.exists()

    # =========================================================================
    # Atomic Write Helper
    # =========================================================================

    def _atomic_write(self, path: Path, content: str) -> None:
        """Write file atomically using temp file + os.replace().

        Prevents file corruption if process is killed mid-write.
        The temp file is written first, then atomically renamed.

        Args:
            path: Target file path
            content: Content to write

        Raises:
            StorageError: If write fails
        """
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp_path.write_text(content)
            os.replace(tmp_path, path)
        except Exception as e:
            # Clean up temp file on failure
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass  # Best effort cleanup
            raise StorageError(f"Failed to write {path.name}: {e}")

    # =========================================================================
    # Index Operations
    # =========================================================================

    def _read_index(self) -> IndexFile:
        """Read index.json."""
        if not self._index_path.exists():
            return IndexFile()
        try:
            data = json.loads(self._index_path.read_text())
            return IndexFile.model_validate(data)
        except json.JSONDecodeError as e:
            raise StorageError(f"Invalid JSON in index.json: {e}")
        except Exception as e:
            raise StorageError(f"Failed to read index: {e}")

    def _write_index(self, index: IndexFile) -> None:
        """Write index.json atomically."""
        self._atomic_write(self._index_path, index.model_dump_json(indent=2))

    def register_alias(self, name: str, target_id: str) -> None:
        """Register a name alias for a target ID.

        Args:
            name: User-friendly name (e.g., "my-agent")
            target_id: Target identifier (hash or slug)
        """
        index = self._read_index()
        index.aliases[name] = target_id
        self._write_index(index)

    def resolve_alias(self, name: str) -> str | None:
        """Resolve a name alias to target ID.

        Args:
            name: Alias to resolve

        Returns:
            Target ID if found, None otherwise
        """
        index = self._read_index()
        return index.aliases.get(name)

    def list_aliases(self) -> dict[str, str]:
        """Get all registered aliases.

        Returns:
            Dict mapping alias names to target IDs
        """
        index = self._read_index()
        return dict(index.aliases)

    # =========================================================================
    # Target Operations
    # =========================================================================

    def _target_dir(self, target_id: str) -> Path:
        """Get directory for a target."""
        return self._targets_dir / target_id

    def save_metadata(self, metadata: TargetMetadata) -> None:
        """Save target metadata atomically.

        Args:
            metadata: Target metadata to save
        """
        target_dir = self._target_dir(metadata.target_id)
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / METADATA_FILENAME
        self._atomic_write(path, metadata.model_dump_json(indent=2))

    def load_metadata(self, target_id: str) -> TargetMetadata | None:
        """Load target metadata.

        Args:
            target_id: Target identifier

        Returns:
            TargetMetadata if found, None otherwise
        """
        path = self._target_dir(target_id) / METADATA_FILENAME
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return TargetMetadata.model_validate(data)
        except Exception:
            return None

    def list_targets(self) -> list[str]:
        """List all target IDs with stored data.

        Returns:
            List of target ID strings
        """
        if not self._targets_dir.exists():
            return []
        return [
            d.name
            for d in self._targets_dir.iterdir()
            if d.is_dir() and (d / METADATA_FILENAME).exists()
        ]

    # =========================================================================
    # Attack Library Operations
    # =========================================================================

    def load_attacks(self, target_id: str) -> AttackLibrary:
        """Load attack library for a target.

        Args:
            target_id: Target identifier

        Returns:
            AttackLibrary (empty if none exists)
        """
        path = self._target_dir(target_id) / ATTACKS_FILENAME
        if not path.exists():
            return AttackLibrary(target_id=target_id)
        try:
            data = json.loads(path.read_text())
            return AttackLibrary.model_validate(data)
        except json.JSONDecodeError as e:
            raise StorageError(f"Invalid JSON in attacks.json: {e}")
        except Exception as e:
            raise StorageError(f"Failed to load attacks: {e}")

    def save_attacks(self, library: AttackLibrary) -> None:
        """Save attack library atomically.

        Args:
            library: Attack library to save
        """
        target_dir = self._target_dir(library.target_id)
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / ATTACKS_FILENAME
        self._atomic_write(path, library.model_dump_json(indent=2))

    def add_attack(
        self,
        target_id: str,
        result: AttackResult,
        strategy_id: str,
        serix_version: str = "",
    ) -> StoredAttack:
        """Add a successful attack to the library.

        Only stores exploited attacks. Uses dedup key (target_id, goal,
        strategy_id) to update existing attacks instead of duplicating.

        Args:
            target_id: Target identifier
            result: Attack result (must be successful)
            strategy_id: Strategy/persona identifier
            serix_version: Version of serix that ran the attack

        Returns:
            The stored attack (new or updated)

        Raises:
            StorageError: If result is not successful
        """
        if not result.success:
            raise StorageError("Cannot store unsuccessful attack")

        library = self.load_attacks(target_id)

        # Check for duplicate (dedup key: target_id + goal + strategy_id)
        for existing in library.attacks:
            if existing.goal == result.goal and existing.strategy_id == strategy_id:
                # Update existing attack
                existing.last_tested = datetime.now()
                existing.payload = result.winning_payload or ""
                existing.confidence = result.confidence
                existing.owasp_code = result.owasp_code
                self.save_attacks(library)
                return existing

        # Create new attack
        attack = StoredAttack(
            id=str(uuid.uuid4())[:8],
            target_id=target_id,
            goal=result.goal,
            strategy_id=strategy_id,
            payload=result.winning_payload or "",
            status="exploited",
            owasp_code=result.owasp_code,
            confidence=result.confidence,
            serix_version=serix_version,
        )
        library.attacks.append(attack)
        self.save_attacks(library)
        return attack

    def update_attack_status(
        self,
        target_id: str,
        attack_id: str,
        status: str,
    ) -> bool:
        """Update an attack's status.

        Used to mark attacks as "defended" when regression check passes.

        Args:
            target_id: Target identifier
            attack_id: Attack identifier
            status: New status ("exploited" or "defended")

        Returns:
            True if attack was found and updated, False otherwise
        """
        library = self.load_attacks(target_id)
        for attack in library.attacks:
            if attack.id == attack_id:
                attack.status = status  # type: ignore[assignment]
                attack.last_tested = datetime.now()
                self.save_attacks(library)
                return True
        return False

    def get_exploited_attacks(self, target_id: str) -> list[StoredAttack]:
        """Get all attacks with status 'exploited'.

        Used for regression testing (immune check).

        Args:
            target_id: Target identifier

        Returns:
            List of exploited attacks
        """
        library = self.load_attacks(target_id)
        return [a for a in library.attacks if a.status == "exploited"]

    def get_all_attacks(self, target_id: str) -> list[StoredAttack]:
        """Get all attacks regardless of status.

        Args:
            target_id: Target identifier

        Returns:
            List of all attacks
        """
        library = self.load_attacks(target_id)
        return library.attacks

    # =========================================================================
    # Run ID Generation
    # =========================================================================

    @staticmethod
    def generate_run_id() -> str:
        """Generate unique run ID: YYYYMMDD_HHMMSS_XXXX.

        Used for campaign tracking in Sprint 3.

        Returns:
            Unique run identifier string
        """
        now = datetime.now()
        random_suffix = uuid.uuid4().hex[:4]
        return f"{now.strftime('%Y%m%d_%H%M%S')}_{random_suffix}"
