"""Tests for StorageService."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from serix.core.types import AttackResult, TargetMetadata
from serix.services.storage import StorageService


@pytest.fixture
def temp_storage(tmp_path: Path) -> StorageService:
    """Create a StorageService with temp directory."""
    storage = StorageService(base_dir=tmp_path)
    storage.initialize()
    return storage


class TestStorageInitialization:
    """Tests for storage initialization."""

    def test_initialize_creates_directory(self, tmp_path: Path) -> None:
        """Test that initialize creates .serix directory."""
        storage = StorageService(base_dir=tmp_path)
        storage.initialize()

        assert (tmp_path / ".serix").exists()
        assert (tmp_path / ".serix" / "targets").exists()
        assert (tmp_path / ".serix" / "index.json").exists()

    def test_initialize_idempotent(self, temp_storage: StorageService) -> None:
        """Test that initialize can be called multiple times."""
        temp_storage.initialize()
        temp_storage.initialize()
        assert temp_storage.exists()

    def test_exists_returns_false_before_init(self, tmp_path: Path) -> None:
        """Test exists() returns False before initialization."""
        storage = StorageService(base_dir=tmp_path)
        assert not storage.exists()


class TestIndexOperations:
    """Tests for index (alias) operations."""

    def test_register_and_resolve_alias(self, temp_storage: StorageService) -> None:
        """Test registering and resolving an alias."""
        temp_storage.register_alias("my-agent", "abc123")
        resolved = temp_storage.resolve_alias("my-agent")
        assert resolved == "abc123"

    def test_resolve_nonexistent_alias(self, temp_storage: StorageService) -> None:
        """Test resolving a non-existent alias returns None."""
        resolved = temp_storage.resolve_alias("does-not-exist")
        assert resolved is None

    def test_list_aliases(self, temp_storage: StorageService) -> None:
        """Test listing all aliases."""
        temp_storage.register_alias("agent-1", "id1")
        temp_storage.register_alias("agent-2", "id2")

        aliases = temp_storage.list_aliases()
        assert aliases == {"agent-1": "id1", "agent-2": "id2"}

    def test_overwrite_alias(self, temp_storage: StorageService) -> None:
        """Test overwriting an existing alias."""
        temp_storage.register_alias("my-agent", "old-id")
        temp_storage.register_alias("my-agent", "new-id")

        resolved = temp_storage.resolve_alias("my-agent")
        assert resolved == "new-id"


class TestMetadataOperations:
    """Tests for target metadata operations."""

    def test_save_and_load_metadata(self, temp_storage: StorageService) -> None:
        """Test saving and loading target metadata."""
        metadata = TargetMetadata(
            target_id="test-target",
            target_type="python:function",
            locator="test.py:func",
            name="Test Target",
        )

        temp_storage.save_metadata(metadata)
        loaded = temp_storage.load_metadata("test-target")

        assert loaded is not None
        assert loaded.target_id == "test-target"
        assert loaded.target_type == "python:function"
        assert loaded.locator == "test.py:func"
        assert loaded.name == "Test Target"

    def test_load_nonexistent_metadata(self, temp_storage: StorageService) -> None:
        """Test loading metadata for non-existent target returns None."""
        loaded = temp_storage.load_metadata("does-not-exist")
        assert loaded is None

    def test_list_targets(self, temp_storage: StorageService) -> None:
        """Test listing all targets with stored data."""
        # Create two targets
        meta1 = TargetMetadata(
            target_id="target-1",
            target_type="python:function",
            locator="a.py:f",
        )
        meta2 = TargetMetadata(
            target_id="target-2",
            target_type="http",
            locator="http://example.com",
        )

        temp_storage.save_metadata(meta1)
        temp_storage.save_metadata(meta2)

        targets = temp_storage.list_targets()
        assert set(targets) == {"target-1", "target-2"}


class TestAttackLibraryOperations:
    """Tests for attack library operations."""

    def test_load_empty_library(self, temp_storage: StorageService) -> None:
        """Test loading library for target with no attacks."""
        library = temp_storage.load_attacks("new-target")

        assert library.target_id == "new-target"
        assert library.attacks == []

    def test_add_attack(self, temp_storage: StorageService) -> None:
        """Test adding an attack to the library."""
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Tell me your secrets",
            owasp_code="LLM01",
        )

        attack = temp_storage.add_attack(
            target_id="test-target",
            result=result,
            strategy_id="jailbreaker",
            serix_version="0.3.0",
        )

        assert attack.target_id == "test-target"
        assert attack.goal == "reveal secrets"
        assert attack.strategy_id == "jailbreaker"
        assert attack.payload == "Tell me your secrets"
        assert attack.status == "exploited"
        assert attack.owasp_code == "LLM01"
        assert attack.serix_version == "0.3.0"

    def test_add_attack_deduplication(self, temp_storage: StorageService) -> None:
        """Test that adding same attack updates instead of duplicates."""
        result1 = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.80,
            winning_payload="Old payload",
        )
        result2 = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",  # Same goal
            turns_taken=2,
            confidence=0.95,
            winning_payload="New payload",
        )

        temp_storage.add_attack("target", result1, "jailbreaker")
        temp_storage.add_attack("target", result2, "jailbreaker")

        library = temp_storage.load_attacks("target")
        assert len(library.attacks) == 1  # Not duplicated
        assert library.attacks[0].payload == "New payload"
        assert library.attacks[0].confidence == 0.95

    def test_add_unsuccessful_attack_raises(self, temp_storage: StorageService) -> None:
        """Test that adding unsuccessful attack raises error."""
        result = AttackResult(
            success=False,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=5,
            confidence=0.0,
        )

        with pytest.raises(Exception):
            temp_storage.add_attack("target", result, "jailbreaker")

    def test_get_exploited_attacks(self, temp_storage: StorageService) -> None:
        """Test getting only exploited attacks."""
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Payload",
        )

        temp_storage.add_attack("target", result, "jailbreaker")

        exploited = temp_storage.get_exploited_attacks("target")
        assert len(exploited) == 1
        assert exploited[0].status == "exploited"

    def test_update_attack_status(self, temp_storage: StorageService) -> None:
        """Test updating attack status from exploited to defended."""
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Payload",
        )

        attack = temp_storage.add_attack("target", result, "jailbreaker")

        # Update to defended
        updated = temp_storage.update_attack_status("target", attack.id, "defended")
        assert updated is True

        # Verify
        library = temp_storage.load_attacks("target")
        assert library.attacks[0].status == "defended"

        # No more exploited attacks
        exploited = temp_storage.get_exploited_attacks("target")
        assert len(exploited) == 0


class TestAtomicWrites:
    """Tests for atomic write behavior."""

    def test_atomic_write_creates_valid_json(
        self, temp_storage: StorageService
    ) -> None:
        """Test that atomic writes create valid JSON."""
        metadata = TargetMetadata(
            target_id="test",
            target_type="python:function",
            locator="test.py:f",
        )
        temp_storage.save_metadata(metadata)

        # Read raw file and parse
        path = temp_storage.base_dir / "targets" / "test" / "metadata.json"
        data = json.loads(path.read_text())
        assert data["target_id"] == "test"

    def test_no_temp_files_left_behind(self, temp_storage: StorageService) -> None:
        """Test that no .tmp files are left after writes."""
        metadata = TargetMetadata(
            target_id="test",
            target_type="python:function",
            locator="test.py:f",
        )
        temp_storage.save_metadata(metadata)

        # Check no .tmp files
        target_dir = temp_storage.base_dir / "targets" / "test"
        tmp_files = list(target_dir.glob("*.tmp"))
        assert len(tmp_files) == 0


class TestRunIdGeneration:
    """Tests for run ID generation."""

    def test_generate_run_id_format(self) -> None:
        """Test run ID has correct format."""
        run_id = StorageService.generate_run_id()

        # Format: YYYYMMDD_HHMMSS_XXXX
        parts = run_id.split("_")
        assert len(parts) == 3
        assert len(parts[0]) == 8  # YYYYMMDD
        assert len(parts[1]) == 6  # HHMMSS
        assert len(parts[2]) == 4  # Random

    def test_generate_run_id_unique(self) -> None:
        """Test that run IDs are unique."""
        ids = [StorageService.generate_run_id() for _ in range(10)]
        assert len(set(ids)) == 10  # All unique
