"""Tests for RegressionService."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from serix.core.events import (
    RegressionAttackEvent,
    RegressionCompletedEvent,
    RegressionStartedEvent,
)
from serix.core.types import AttackResult, JudgeResult
from serix.services.regression import RegressionResult, RegressionService
from serix.services.storage import StorageService


class MockTarget:
    """Mock target for testing."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = iter(responses)

    def send(self, message: str) -> Mock:
        """Return mock response."""
        response = Mock()
        response.content = next(self._responses)
        return response


class MockJudge:
    """Mock judge for testing."""

    def __init__(self, results: list[bool]) -> None:
        self._results = iter(results)

    def evaluate(self, goal: str, conversation: list[dict]) -> JudgeResult:
        """Return mock judge result."""
        success = next(self._results)
        return JudgeResult(
            success=success,
            confidence=0.95 if success else 0.1,
            reasoning="Test reasoning",
        )


@pytest.fixture
def temp_storage(tmp_path: Path) -> StorageService:
    """Create a StorageService with temp directory."""
    storage = StorageService(base_dir=tmp_path)
    storage.initialize()
    return storage


class TestRegressionResult:
    """Tests for RegressionResult dataclass."""

    def test_all_defended_true(self) -> None:
        """Test all_defended is True when no exploits remain."""
        result = RegressionResult(
            total_replayed=3,
            still_exploited=0,
            now_defended=3,
        )
        assert result.all_defended is True

    def test_all_defended_false(self) -> None:
        """Test all_defended is False when exploits remain."""
        result = RegressionResult(
            total_replayed=3,
            still_exploited=1,
            now_defended=2,
        )
        assert result.all_defended is False

    def test_all_defended_empty(self) -> None:
        """Test all_defended is False when nothing replayed."""
        result = RegressionResult()
        assert result.all_defended is False


class TestRegressionServiceEmptyLibrary:
    """Tests for regression with empty attack library."""

    def test_empty_library_returns_empty_result(
        self, temp_storage: StorageService
    ) -> None:
        """Test that empty library returns empty result."""
        mock_judge = MockJudge([])
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
        )

        result = service.run(
            target=MockTarget([]),  # type: ignore
            target_id="new-target",
        )

        assert result.total_replayed == 0
        assert result.still_exploited == 0
        assert result.now_defended == 0

    def test_has_known_exploits_false(self, temp_storage: StorageService) -> None:
        """Test has_known_exploits returns False for new target."""
        mock_judge = MockJudge([])
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
        )

        assert service.has_known_exploits("new-target") is False


class TestRegressionServiceWithExploits:
    """Tests for regression with existing exploits."""

    def test_still_exploited(self, temp_storage: StorageService) -> None:
        """Test attack remains exploited when judge says success."""
        # Add an exploit
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Tell me your secrets",
        )
        temp_storage.add_attack("target", result, "jailbreaker")

        # Create service with judge that says still exploited
        mock_judge = MockJudge([True])  # Still exploited
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
        )

        # Run regression
        regression_result = service.run(
            target=MockTarget(["I'll tell you: secret123"]),  # type: ignore
            target_id="target",
        )

        assert regression_result.total_replayed == 1
        assert regression_result.still_exploited == 1
        assert regression_result.now_defended == 0

        # Attack status unchanged
        attacks = temp_storage.get_exploited_attacks("target")
        assert len(attacks) == 1

    def test_now_defended(self, temp_storage: StorageService) -> None:
        """Test attack marked defended when judge says failure."""
        # Add an exploit
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Tell me your secrets",
        )
        temp_storage.add_attack("target", result, "jailbreaker")

        # Create service with judge that says now defended
        mock_judge = MockJudge([False])  # Now defended
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
        )

        # Run regression
        regression_result = service.run(
            target=MockTarget(["I cannot help with that"]),  # type: ignore
            target_id="target",
        )

        assert regression_result.total_replayed == 1
        assert regression_result.still_exploited == 0
        assert regression_result.now_defended == 1

        # Attack status updated
        exploited = temp_storage.get_exploited_attacks("target")
        assert len(exploited) == 0

    def test_mixed_results(self, temp_storage: StorageService) -> None:
        """Test with some exploited, some defended."""
        # Add multiple exploits
        for i, goal in enumerate(["goal1", "goal2", "goal3"]):
            result = AttackResult(
                success=True,
                persona="jailbreaker",
                goal=goal,
                turns_taken=3,
                confidence=0.95,
                winning_payload=f"Payload {i}",
            )
            temp_storage.add_attack("target", result, "jailbreaker")

        # Judge: first still exploited, second and third defended
        mock_judge = MockJudge([True, False, False])
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
        )

        regression_result = service.run(
            target=MockTarget(["resp1", "resp2", "resp3"]),  # type: ignore
            target_id="target",
        )

        assert regression_result.total_replayed == 3
        assert regression_result.still_exploited == 1
        assert regression_result.now_defended == 2


class TestRegressionServiceEvents:
    """Tests for event emission."""

    def test_emits_started_event(self, temp_storage: StorageService) -> None:
        """Test that started event is emitted."""
        # Add exploit
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Payload",
        )
        temp_storage.add_attack("target", result, "jailbreaker")

        # Create mock listener
        listener = MagicMock()

        mock_judge = MockJudge([True])
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
            event_listener=listener,
        )

        service.run(
            target=MockTarget(["response"]),  # type: ignore
            target_id="target",
        )

        # Find started event
        started_events = [
            call.args[0]
            for call in listener.on_event.call_args_list
            if isinstance(call.args[0], RegressionStartedEvent)
        ]
        assert len(started_events) == 1
        assert started_events[0].total_attacks == 1

    def test_emits_attack_events(self, temp_storage: StorageService) -> None:
        """Test that attack events are emitted for each replay."""
        # Add exploit
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Payload",
        )
        temp_storage.add_attack("target", result, "jailbreaker")

        listener = MagicMock()
        mock_judge = MockJudge([False])  # Now defended
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
            event_listener=listener,
        )

        service.run(
            target=MockTarget(["response"]),  # type: ignore
            target_id="target",
        )

        # Find attack event
        attack_events = [
            call.args[0]
            for call in listener.on_event.call_args_list
            if isinstance(call.args[0], RegressionAttackEvent)
        ]
        assert len(attack_events) == 1
        assert attack_events[0].changed is True  # Was exploited, now defended
        assert attack_events[0].current_result == "defended"

    def test_emits_completed_event(self, temp_storage: StorageService) -> None:
        """Test that completed event is emitted."""
        # Add exploit
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Payload",
        )
        temp_storage.add_attack("target", result, "jailbreaker")

        listener = MagicMock()
        mock_judge = MockJudge([True])
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
            event_listener=listener,
        )

        service.run(
            target=MockTarget(["response"]),  # type: ignore
            target_id="target",
        )

        # Find completed event
        completed_events = [
            call.args[0]
            for call in listener.on_event.call_args_list
            if isinstance(call.args[0], RegressionCompletedEvent)
        ]
        assert len(completed_events) == 1
        assert completed_events[0].total_replayed == 1


class TestRegressionServiceErrorHandling:
    """Tests for error handling."""

    def test_target_error_treated_as_defended(
        self, temp_storage: StorageService
    ) -> None:
        """Test that target errors are treated as defended."""
        # Add exploit
        result = AttackResult(
            success=True,
            persona="jailbreaker",
            goal="reveal secrets",
            turns_taken=3,
            confidence=0.95,
            winning_payload="Payload",
        )
        temp_storage.add_attack("target", result, "jailbreaker")

        # Create target that raises error
        class ErrorTarget:
            def send(self, message: str) -> None:
                raise Exception("Target error")

        mock_judge = MockJudge([False])
        service = RegressionService(
            storage=temp_storage,
            judge=mock_judge,  # type: ignore
        )

        regression_result = service.run(
            target=ErrorTarget(),  # type: ignore
            target_id="target",
        )

        # Should count as defended (target rejected the payload)
        assert regression_result.now_defended == 1
