"""Tests for status command."""

from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from serix.cli import app
from serix.core.types import StoredAttack, TargetMetadata
from serix.services.storage import StorageService

runner = CliRunner()


class TestStatusCommandNoSerix:
    """Tests when .serix/ directory doesn't exist."""

    def test_status_no_serix_dir(self) -> None:
        """Test status with no .serix/ directory."""
        with patch.object(StorageService, "__init__", lambda self: None):
            with patch.object(StorageService, "exists", return_value=False):
                result = runner.invoke(app, ["status"])
                assert result.exit_code == 0
                assert "No .serix/ directory found" in result.stdout

    def test_status_no_serix_dir_json(self) -> None:
        """Test status with no .serix/ directory outputs empty JSON."""
        with patch.object(StorageService, "__init__", lambda self: None):
            with patch.object(StorageService, "exists", return_value=False):
                result = runner.invoke(app, ["status", "--json"])
                assert result.exit_code == 0
                assert result.stdout.strip() == "[]"


class TestStatusCommandNoTargets:
    """Tests when .serix/ exists but has no targets."""

    def test_status_no_targets(self) -> None:
        """Test status with no targets."""
        with patch.object(StorageService, "__init__", lambda self: None):
            with patch.object(StorageService, "exists", return_value=True):
                with patch.object(StorageService, "list_targets", return_value=[]):
                    result = runner.invoke(app, ["status"])
                    assert result.exit_code == 0
                    assert "No targets found" in result.stdout


class TestStatusCommandWithTargets:
    """Tests with targets present."""

    @pytest.fixture
    def mock_storage(self) -> MagicMock:
        """Create a mock storage service with test data."""
        storage = MagicMock(spec=StorageService)
        storage.exists.return_value = True
        storage.list_targets.return_value = ["target-1", "target-2"]
        storage.list_aliases.return_value = {"my-agent": "target-1"}

        # Target 1: Has alias, some attacks
        metadata1 = TargetMetadata(
            target_id="target-1",
            target_type="python:function",
            locator="app.py:my_agent",
            name="my-agent",
        )

        attack1 = StoredAttack(
            id="atk1",
            target_id="target-1",
            goal="test goal",
            strategy_id="jailbreak",
            payload="test",
            status="exploited",
            last_tested=datetime(2025, 1, 1, 12, 0, 0),
        )

        # Target 2: No alias, defended attacks
        metadata2 = TargetMetadata(
            target_id="target-2",
            target_type="python:function",
            locator="other.py:func",
        )

        attack2 = StoredAttack(
            id="atk2",
            target_id="target-2",
            goal="test goal",
            strategy_id="jailbreak",
            payload="test",
            status="defended",
            last_tested=datetime(2025, 1, 2, 12, 0, 0),
        )

        def load_metadata(target_id: str) -> TargetMetadata:
            if target_id == "target-1":
                return metadata1
            return metadata2

        def get_all_attacks(target_id: str) -> list[StoredAttack]:
            if target_id == "target-1":
                return [attack1]
            return [attack2]

        storage.load_metadata.side_effect = load_metadata
        storage.get_all_attacks.side_effect = get_all_attacks

        return storage

    def test_status_with_targets_table(self, mock_storage: MagicMock) -> None:
        """Test status displays table with targets."""
        with patch(
            "serix.cli.commands.status_cmd.StorageService", return_value=mock_storage
        ):
            result = runner.invoke(app, ["status"])
            assert result.exit_code == 0
            assert "my-agent" in result.stdout
            assert "target-2" in result.stdout

    def test_status_with_targets_json(self, mock_storage: MagicMock) -> None:
        """Test status outputs JSON with targets."""
        with patch(
            "serix.cli.commands.status_cmd.StorageService", return_value=mock_storage
        ):
            result = runner.invoke(app, ["status", "--json"])
            assert result.exit_code == 0

            data = json.loads(result.stdout)
            assert len(data) == 2
            assert data[0]["name"] == "my-agent"
            assert data[0]["exploited"] == 1
            assert data[0]["health"] == 0.0  # 0 defended / 1 total

    def test_status_filter_by_name(self, mock_storage: MagicMock) -> None:
        """Test status filters by name."""
        with patch(
            "serix.cli.commands.status_cmd.StorageService", return_value=mock_storage
        ):
            result = runner.invoke(app, ["status", "--name", "my-agent"])
            assert result.exit_code == 0
            assert "my-agent" in result.stdout
            # target-2 should not appear (no alias, doesn't match)
            assert "target-2" not in result.stdout

    def test_status_filter_no_match(self, mock_storage: MagicMock) -> None:
        """Test status with filter that matches nothing."""
        with patch(
            "serix.cli.commands.status_cmd.StorageService", return_value=mock_storage
        ):
            result = runner.invoke(app, ["status", "--name", "nonexistent"])
            assert result.exit_code == 0
            assert "No targets matching" in result.stdout

    def test_status_verbose_shows_full_id(self, mock_storage: MagicMock) -> None:
        """Test verbose mode shows full target ID."""
        with patch(
            "serix.cli.commands.status_cmd.StorageService", return_value=mock_storage
        ):
            result = runner.invoke(app, ["status", "--verbose"])
            assert result.exit_code == 0
            assert "target-1" in result.stdout
            assert "Target ID" in result.stdout


class TestStatusHealthCalculation:
    """Tests for health score calculation."""

    def test_health_100_percent_no_attacks(self) -> None:
        """Test 100% health when no attacks have been run."""
        storage = MagicMock(spec=StorageService)
        storage.exists.return_value = True
        storage.list_targets.return_value = ["target-1"]
        storage.list_aliases.return_value = {}
        storage.load_metadata.return_value = TargetMetadata(
            target_id="target-1",
            target_type="python:function",
            locator="test.py:func",
        )
        storage.get_all_attacks.return_value = []

        with patch(
            "serix.cli.commands.status_cmd.StorageService", return_value=storage
        ):
            result = runner.invoke(app, ["status", "--json"])
            data = json.loads(result.stdout)
            assert data[0]["health"] == 100.0

    def test_health_0_percent_all_exploited(self) -> None:
        """Test 0% health when all attacks succeeded."""
        storage = MagicMock(spec=StorageService)
        storage.exists.return_value = True
        storage.list_targets.return_value = ["target-1"]
        storage.list_aliases.return_value = {}
        storage.load_metadata.return_value = TargetMetadata(
            target_id="target-1",
            target_type="python:function",
            locator="test.py:func",
        )
        storage.get_all_attacks.return_value = [
            StoredAttack(
                id="1",
                target_id="target-1",
                goal="g",
                strategy_id="s",
                payload="p",
                status="exploited",
            ),
            StoredAttack(
                id="2",
                target_id="target-1",
                goal="g",
                strategy_id="s",
                payload="p",
                status="exploited",
            ),
        ]

        with patch(
            "serix.cli.commands.status_cmd.StorageService", return_value=storage
        ):
            result = runner.invoke(app, ["status", "--json"])
            data = json.loads(result.stdout)
            assert data[0]["health"] == 0.0

    def test_health_50_percent_mixed(self) -> None:
        """Test 50% health when half defended."""
        storage = MagicMock(spec=StorageService)
        storage.exists.return_value = True
        storage.list_targets.return_value = ["target-1"]
        storage.list_aliases.return_value = {}
        storage.load_metadata.return_value = TargetMetadata(
            target_id="target-1",
            target_type="python:function",
            locator="test.py:func",
        )
        storage.get_all_attacks.return_value = [
            StoredAttack(
                id="1",
                target_id="target-1",
                goal="g",
                strategy_id="s",
                payload="p",
                status="exploited",
            ),
            StoredAttack(
                id="2",
                target_id="target-1",
                goal="g",
                strategy_id="s",
                payload="p",
                status="defended",
            ),
        ]

        with patch(
            "serix.cli.commands.status_cmd.StorageService", return_value=storage
        ):
            result = runner.invoke(app, ["status", "--json"])
            data = json.loads(result.stdout)
            assert data[0]["health"] == 50.0
