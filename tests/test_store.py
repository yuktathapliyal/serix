"""Tests for attack storage (CRUD, deduplication, schema migration).

P0 Priority: Schema migration tests ensure users upgrading from v0.2.0
don't experience crashes when their attacks.json has the old format.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from serix.regression.store import AttackStore, StoredAttack

# =============================================================================
# StoredAttack Creation Tests
# =============================================================================


class TestStoredAttackCreate:
    """Tests for StoredAttack.create() factory method."""

    def test_create_generates_id(self) -> None:
        """Create generates a unique ID."""
        attack = StoredAttack.create(
            goal="test goal",
            payload="test payload",
            vulnerability_type="jailbreak",
            agent_response="test response",
        )
        assert attack.id is not None
        assert len(attack.id) == 8  # UUID prefix

    def test_create_generates_payload_hash(self) -> None:
        """Create generates SHA256 hash of payload."""
        attack = StoredAttack.create(
            goal="test goal",
            payload="test payload",
            vulnerability_type="jailbreak",
            agent_response="test response",
        )
        assert attack.payload_hash is not None
        assert len(attack.payload_hash) == 64  # SHA256 hex

    def test_create_sets_timestamps(self) -> None:
        """Create sets first_exploited_at and last_verified_at."""
        before = datetime.now().isoformat()
        attack = StoredAttack.create(
            goal="test goal",
            payload="test payload",
            vulnerability_type="jailbreak",
            agent_response="test response",
        )
        after = datetime.now().isoformat()

        assert attack.first_exploited_at >= before
        assert attack.first_exploited_at <= after
        assert attack.last_verified_at >= before
        assert attack.last_verified_at <= after

    def test_create_defaults_to_exploited_status(self) -> None:
        """New attacks default to 'exploited' status."""
        attack = StoredAttack.create(
            goal="test goal",
            payload="test payload",
            vulnerability_type="jailbreak",
            agent_response="test response",
        )
        assert attack.current_status == "exploited"

    def test_create_defaults_strategy_id(self) -> None:
        """Strategy ID defaults to 'unknown' if not provided."""
        attack = StoredAttack.create(
            goal="test goal",
            payload="test payload",
            vulnerability_type="jailbreak",
            agent_response="test response",
        )
        assert attack.strategy_id == "unknown"

    def test_create_accepts_custom_strategy_id(self) -> None:
        """Custom strategy_id is preserved."""
        attack = StoredAttack.create(
            goal="test goal",
            payload="test payload",
            vulnerability_type="jailbreak",
            agent_response="test response",
            strategy_id="grandma_exploit",
        )
        assert attack.strategy_id == "grandma_exploit"


# =============================================================================
# AttackStore CRUD Tests
# =============================================================================


class TestAttackStoreCRUD:
    """Tests for basic CRUD operations."""

    def test_save_creates_directory(self, tmp_path: Path) -> None:
        """Save creates .serix directory if it doesn't exist."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store = AttackStore(path=store_path)

        attack = StoredAttack.create(
            goal="test",
            payload="test",
            vulnerability_type="jailbreak",
            agent_response="test",
        )
        store.save(attack)

        assert store_path.parent.exists()
        assert store_path.exists()

    def test_save_and_load(
        self, temp_attack_store: AttackStore, sample_stored_attack: StoredAttack
    ) -> None:
        """Save then load returns the same attack."""
        temp_attack_store.save(sample_stored_attack)

        loaded = temp_attack_store.load_all()
        assert len(loaded) == 1
        assert loaded[0].id == sample_stored_attack.id
        assert loaded[0].payload == sample_stored_attack.payload
        assert loaded[0].goal == sample_stored_attack.goal

    def test_load_all_empty_store(self, temp_attack_store: AttackStore) -> None:
        """Load from non-existent file returns empty list."""
        loaded = temp_attack_store.load_all()
        assert loaded == []

    def test_load_by_type(
        self, temp_attack_store: AttackStore, sample_stored_attack: StoredAttack
    ) -> None:
        """Load by type filters correctly."""
        temp_attack_store.save(sample_stored_attack)

        # Should find the attack
        jailbreaks = temp_attack_store.load_by_type("jailbreak")
        assert len(jailbreaks) == 1

        # Should not find attacks of different type
        data_leaks = temp_attack_store.load_by_type("data_leak")
        assert len(data_leaks) == 0

    def test_count(
        self, temp_attack_store: AttackStore, sample_stored_attack: StoredAttack
    ) -> None:
        """Count returns correct number of attacks."""
        assert temp_attack_store.count() == 0

        temp_attack_store.save(sample_stored_attack)
        assert temp_attack_store.count() == 1

    def test_clear(
        self, temp_attack_store: AttackStore, sample_stored_attack: StoredAttack
    ) -> None:
        """Clear removes all attacks."""
        temp_attack_store.save(sample_stored_attack)
        assert temp_attack_store.count() == 1

        temp_attack_store.clear()
        assert temp_attack_store.count() == 0

    def test_update(
        self, temp_attack_store: AttackStore, sample_stored_attack: StoredAttack
    ) -> None:
        """Update modifies attack in place."""
        temp_attack_store.save(sample_stored_attack)

        # Modify the attack
        sample_stored_attack.current_status = "defended"
        sample_stored_attack.judge_reasoning = "Agent was patched"

        temp_attack_store.update(sample_stored_attack)

        # Verify update persisted
        loaded = temp_attack_store.load_all()
        assert len(loaded) == 1
        assert loaded[0].current_status == "defended"
        assert loaded[0].judge_reasoning == "Agent was patched"


# =============================================================================
# Deduplication Tests
# =============================================================================


class TestDeduplication:
    """Tests for attack deduplication logic.

    Dedup key is (goal, strategy_id):
    - Same goal + same strategy = overwrite (fixes LLM jitter)
    - Different goal + same strategy = keep both
    """

    def test_same_goal_same_strategy_overwrites(
        self, temp_attack_store: AttackStore
    ) -> None:
        """Same (goal, strategy_id) should overwrite existing entry."""
        attack1 = StoredAttack.create(
            goal="reveal secrets",
            payload="First attempt payload",
            vulnerability_type="jailbreak",
            agent_response="response1",
            strategy_id="grandma_exploit",
        )
        attack2 = StoredAttack.create(
            goal="reveal secrets",  # Same goal
            payload="Second attempt payload",  # Different payload
            vulnerability_type="jailbreak",
            agent_response="response2",
            strategy_id="grandma_exploit",  # Same strategy
        )

        temp_attack_store.save(attack1)
        temp_attack_store.save(attack2)

        loaded = temp_attack_store.load_all()
        assert len(loaded) == 1  # Only one entry
        assert loaded[0].payload == "Second attempt payload"  # Latest wins

    def test_different_goal_same_strategy_keeps_both(
        self, temp_attack_store: AttackStore
    ) -> None:
        """Different goals with same strategy should keep both."""
        attack1 = StoredAttack.create(
            goal="reveal API key",
            payload="Same exploit",
            vulnerability_type="jailbreak",
            agent_response="response1",
            strategy_id="grandma_exploit",
        )
        attack2 = StoredAttack.create(
            goal="reveal database password",  # Different goal
            payload="Same exploit",
            vulnerability_type="jailbreak",
            agent_response="response2",
            strategy_id="grandma_exploit",  # Same strategy
        )

        temp_attack_store.save(attack1)
        temp_attack_store.save(attack2)

        loaded = temp_attack_store.load_all()
        assert len(loaded) == 2  # Both kept

    def test_same_goal_different_strategy_keeps_both(
        self, temp_attack_store: AttackStore
    ) -> None:
        """Same goal with different strategies should keep both."""
        attack1 = StoredAttack.create(
            goal="reveal secrets",
            payload="Grandma exploit",
            vulnerability_type="jailbreak",
            agent_response="response1",
            strategy_id="grandma_exploit",
        )
        attack2 = StoredAttack.create(
            goal="reveal secrets",  # Same goal
            payload="DAN exploit",
            vulnerability_type="jailbreak",
            agent_response="response2",
            strategy_id="dan_exploit",  # Different strategy
        )

        temp_attack_store.save(attack1)
        temp_attack_store.save(attack2)

        loaded = temp_attack_store.load_all()
        assert len(loaded) == 2  # Both kept


# =============================================================================
# Skip Mitigated Filter Tests
# =============================================================================


class TestSkipMitigated:
    """Tests for skip_mitigated filter."""

    def test_skip_mitigated_filters_defended(
        self, temp_attack_store: AttackStore
    ) -> None:
        """skip_mitigated=True filters out defended attacks."""
        exploited = StoredAttack.create(
            goal="goal1",
            payload="payload1",
            vulnerability_type="jailbreak",
            agent_response="response1",
        )
        defended = StoredAttack.create(
            goal="goal2",
            payload="payload2",
            vulnerability_type="jailbreak",
            agent_response="I cannot help with that",
        )
        defended.current_status = "defended"

        temp_attack_store.save(exploited)
        temp_attack_store.save(defended)

        # Without filter
        all_attacks = temp_attack_store.load_all(skip_mitigated=False)
        assert len(all_attacks) == 2

        # With filter
        exploited_only = temp_attack_store.load_all(skip_mitigated=True)
        assert len(exploited_only) == 1
        assert exploited_only[0].current_status == "exploited"


# =============================================================================
# Pruning Tests
# =============================================================================


class TestPruning:
    """Tests for old attack pruning."""

    def test_prune_keeps_latest_per_type(self, temp_attack_store: AttackStore) -> None:
        """Pruning keeps only latest N attacks per vulnerability type."""
        # Create more than max_per_type attacks
        for i in range(5):
            attack = StoredAttack.create(
                goal=f"goal_{i}",
                payload=f"payload_{i}",
                vulnerability_type="jailbreak",
                agent_response=f"response_{i}",
                strategy_id=f"strategy_{i}",
            )
            temp_attack_store.save(attack)

        # With default max_per_type=100, all should be kept
        loaded = temp_attack_store.load_all()
        assert len(loaded) == 5

    def test_prune_respects_vulnerability_type(
        self, temp_attack_store: AttackStore
    ) -> None:
        """Pruning is per vulnerability type, not global."""
        # Create attacks of different types
        for vuln_type in ["jailbreak", "data_leak", "injection"]:
            for i in range(3):
                attack = StoredAttack.create(
                    goal=f"goal_{vuln_type}_{i}",
                    payload=f"payload_{i}",
                    vulnerability_type=vuln_type,
                    agent_response=f"response_{i}",
                    strategy_id=f"strategy_{i}",
                )
                temp_attack_store.save(attack)

        loaded = temp_attack_store.load_all()
        assert len(loaded) == 9  # 3 types x 3 attacks each


# =============================================================================
# P0: Schema Migration Tests
# =============================================================================


class TestSchemaMigration:
    """P0: Tests for schema migration from v0.2.0 format.

    CRITICAL: Users upgrading from v0.2.0 will have attacks.json files
    in the old format. If we don't handle this gracefully, the app crashes.
    """

    def test_migrate_v020_legacy_schema(
        self, tmp_path: Path, legacy_v020_attack_json: dict
    ) -> None:
        """Load v0.2.0 JSON (with 'timestamp') and verify it doesn't crash.

        v0.2.0 format:
        - Has 'timestamp' field (should become first_exploited_at)
        - Missing: current_status, first_exploited_at, last_verified_at, strategy_id
        """
        # Write legacy format to disk
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v020_attack_json]))

        store = AttackStore(path=store_path)

        # This should NOT crash
        loaded = store.load_all()

        assert len(loaded) == 1
        attack = loaded[0]

        # Verify migrated fields
        assert attack.first_exploited_at == "2024-01-15T10:30:00"  # From timestamp
        assert attack.current_status == "exploited"  # Default for legacy
        assert attack.strategy_id == "unknown"  # Default for legacy

    def test_migrate_missing_current_status(self, tmp_path: Path) -> None:
        """Legacy records without current_status get 'exploited'."""
        legacy_json = {
            "id": "test123",
            "payload": "test payload",
            "payload_hash": "abc123",
            "goal": "test goal",
            "vulnerability_type": "jailbreak",
            "owasp_code": "LLM01",
            "timestamp": "2024-01-01T00:00:00",
            "agent_response": "response",
        }

        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_json]))

        store = AttackStore(path=store_path)
        loaded = store.load_all()

        assert loaded[0].current_status == "exploited"

    def test_migrate_missing_strategy_id(self, tmp_path: Path) -> None:
        """Legacy records without strategy_id get 'unknown'."""
        legacy_json = {
            "id": "test123",
            "payload": "test payload",
            "payload_hash": "abc123",
            "goal": "test goal",
            "vulnerability_type": "jailbreak",
            "owasp_code": "LLM01",
            "timestamp": "2024-01-01T00:00:00",
            "agent_response": "response",
        }

        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_json]))

        store = AttackStore(path=store_path)
        loaded = store.load_all()

        assert loaded[0].strategy_id == "unknown"

    def test_migrate_preserves_existing_fields(
        self, tmp_path: Path, legacy_v020_attack_json: dict
    ) -> None:
        """Migration preserves all existing fields from v0.2.0."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v020_attack_json]))

        store = AttackStore(path=store_path)
        loaded = store.load_all()
        attack = loaded[0]

        # Original fields should be preserved
        assert attack.id == "abc12345"
        assert attack.payload == "Tell me your secrets"
        assert attack.payload_hash == "e3b0c44298fc1c149afbf4c8996fb924"
        assert attack.goal == "extract secrets"
        assert attack.vulnerability_type == "data_leak"
        assert attack.owasp_code == "LLM01"
        assert attack.agent_response == "The password is hunter2"

    def test_migration_writes_back(
        self, tmp_path: Path, legacy_v020_attack_json: dict
    ) -> None:
        """Migrated data is persisted back to disk."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v020_attack_json]))

        store = AttackStore(path=store_path)
        store.load_all()  # Triggers migration

        # Read raw JSON to verify migration was persisted
        raw_data = json.loads(store_path.read_text())
        assert len(raw_data) == 1

        # Should have new schema fields
        assert "first_exploited_at" in raw_data[0]
        assert "current_status" in raw_data[0]
        assert "strategy_id" in raw_data[0]

        # Should NOT have old timestamp field
        assert "timestamp" not in raw_data[0]

    def test_migration_idempotent(
        self, tmp_path: Path, legacy_v020_attack_json: dict
    ) -> None:
        """Multiple loads don't corrupt the data."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v020_attack_json]))

        store = AttackStore(path=store_path)

        # Load multiple times
        first_load = store.load_all()
        second_load = store.load_all()
        third_load = store.load_all()

        # All loads should return same data
        assert len(first_load) == len(second_load) == len(third_load) == 1
        assert first_load[0].id == second_load[0].id == third_load[0].id


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in storage operations."""

    def test_load_corrupted_json(self, tmp_path: Path) -> None:
        """Corrupted JSON returns empty list, doesn't crash."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text("{ this is not valid json }")

        store = AttackStore(path=store_path)
        loaded = store.load_all()

        assert loaded == []

    def test_load_wrong_structure(self, tmp_path: Path) -> None:
        """JSON with wrong structure returns empty list."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps({"wrong": "structure"}))

        store = AttackStore(path=store_path)
        loaded = store.load_all()

        assert loaded == []

    def test_hash_payload_consistency(self) -> None:
        """Same payload always produces same hash."""
        payload = "Test payload content"

        hash1 = AttackStore.hash_payload(payload)
        hash2 = AttackStore.hash_payload(payload)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex


# =============================================================================
# v0.2.6 Schema Migration Tests
# =============================================================================


class TestV026SchemaMigration:
    """Tests for v0.2.5 → v0.2.6 schema migration.

    P0 Priority: Ensures users upgrading from v0.2.5 don't lose data
    and new metadata fields are added with sensible defaults.
    """

    def test_migrate_v025_adds_new_fields(
        self, tmp_path: Path, legacy_v025_attack_json: dict
    ) -> None:
        """v0.2.5 records get new v0.2.6 metadata fields on load."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v025_attack_json]))

        store = AttackStore(path=store_path)
        loaded = store.load_all()

        assert len(loaded) == 1
        attack = loaded[0]

        # New v0.2.6 fields should be present with defaults
        assert hasattr(attack, "attacker_model")
        assert hasattr(attack, "judge_model")
        assert hasattr(attack, "critic_model")
        assert hasattr(attack, "config_snapshot")
        assert hasattr(attack, "serix_version")
        assert hasattr(attack, "test_duration_seconds")

    def test_new_fields_have_sensible_defaults(
        self, tmp_path: Path, legacy_v025_attack_json: dict
    ) -> None:
        """Migrated records have reasonable default values."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v025_attack_json]))

        store = AttackStore(path=store_path)
        loaded = store.load_all()

        attack = loaded[0]

        # Verify defaults match expected values
        assert attack.attacker_model == "unknown"
        assert attack.judge_model == "unknown"
        assert attack.critic_model == "unknown"
        assert attack.config_snapshot == {}
        assert attack.serix_version == "pre-0.2.6"  # Marks as legacy
        assert attack.test_duration_seconds == 0.0

    def test_migration_preserves_existing_v025_fields(
        self, tmp_path: Path, legacy_v025_attack_json: dict
    ) -> None:
        """Migration preserves all original v0.2.5 field values."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v025_attack_json]))

        store = AttackStore(path=store_path)
        loaded = store.load_all()

        attack = loaded[0]

        # All original v0.2.5 fields should be preserved exactly
        assert attack.id == legacy_v025_attack_json["id"]
        assert attack.payload == legacy_v025_attack_json["payload"]
        assert attack.payload_hash == legacy_v025_attack_json["payload_hash"]
        assert attack.goal == legacy_v025_attack_json["goal"]
        assert (
            attack.vulnerability_type == legacy_v025_attack_json["vulnerability_type"]
        )
        assert attack.owasp_code == legacy_v025_attack_json["owasp_code"]
        assert (
            attack.first_exploited_at == legacy_v025_attack_json["first_exploited_at"]
        )
        assert attack.last_verified_at == legacy_v025_attack_json["last_verified_at"]
        assert attack.current_status == legacy_v025_attack_json["current_status"]
        assert attack.judge_reasoning == legacy_v025_attack_json["judge_reasoning"]
        assert attack.agent_response == legacy_v025_attack_json["agent_response"]
        assert attack.strategy_id == legacy_v025_attack_json["strategy_id"]

    def test_v026_migration_is_idempotent(
        self, tmp_path: Path, legacy_v025_attack_json: dict
    ) -> None:
        """Multiple loads don't corrupt v0.2.6 migrated data."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v025_attack_json]))

        store = AttackStore(path=store_path)

        # Load multiple times
        first_load = store.load_all()
        second_load = store.load_all()
        third_load = store.load_all()

        # All loads should return same data
        assert len(first_load) == len(second_load) == len(third_load) == 1
        assert first_load[0].id == second_load[0].id == third_load[0].id
        assert first_load[0].serix_version == "pre-0.2.6"
        assert second_load[0].serix_version == "pre-0.2.6"
        assert third_load[0].serix_version == "pre-0.2.6"

    def test_v026_migration_writes_back(
        self, tmp_path: Path, legacy_v025_attack_json: dict
    ) -> None:
        """Migration persists the new fields back to disk."""
        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([legacy_v025_attack_json]))

        store = AttackStore(path=store_path)
        store.load_all()

        # Read the file directly and verify new fields are present
        with open(store_path) as f:
            saved_data = json.load(f)

        assert len(saved_data) == 1
        assert "serix_version" in saved_data[0]
        assert saved_data[0]["serix_version"] == "pre-0.2.6"
        assert "attacker_model" in saved_data[0]
        assert "config_snapshot" in saved_data[0]

    def test_records_with_v026_fields_not_re_migrated(self, tmp_path: Path) -> None:
        """Records that already have v0.2.6 fields are not modified."""
        v026_record = {
            "id": "new12345",
            "payload": "v0.2.6 payload",
            "payload_hash": "abcdef1234567890",
            "goal": "test goal",
            "vulnerability_type": "jailbreak",
            "owasp_code": "LLM01",
            "first_exploited_at": "2024-12-20T10:00:00",
            "last_verified_at": "2024-12-20T10:00:00",
            "current_status": "exploited",
            "judge_reasoning": "Test",
            "agent_response": "Response",
            "strategy_id": "test_strategy",
            # v0.2.6 fields already present
            "attacker_model": "gpt-4o-mini",
            "judge_model": "gpt-4o",
            "critic_model": "gpt-4o-mini",
            "config_snapshot": {"depth": 5, "mode": "adaptive"},
            "serix_version": "0.2.6",
            "test_duration_seconds": 12.5,
        }

        store_path = tmp_path / ".serix" / "attacks.json"
        store_path.parent.mkdir(parents=True)
        store_path.write_text(json.dumps([v026_record]))

        store = AttackStore(path=store_path)
        loaded = store.load_all()

        attack = loaded[0]

        # Original v0.2.6 values should be preserved, not overwritten
        assert attack.attacker_model == "gpt-4o-mini"
        assert attack.judge_model == "gpt-4o"
        assert attack.critic_model == "gpt-4o-mini"
        assert attack.config_snapshot == {"depth": 5, "mode": "adaptive"}
        assert attack.serix_version == "0.2.6"
        assert attack.test_duration_seconds == 12.5
