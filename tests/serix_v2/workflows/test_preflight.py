"""
Tests for preflight check functionality.

Tests that the workflow fails fast with a clear error when
the target cannot be reached.
"""

import pytest

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import ProgressEvent, ProgressPhase
from serix_v2.core.errors import TargetUnreachableError
from serix_v2.workflows.test_workflow import TestWorkflow
from tests.serix_v2.mocks import MockAttackStore, MockCampaignStore, MockLLMProvider


class MockTarget:
    """Mock target for testing."""

    def __init__(self, response: str = "ok", raise_error: bool = False):
        self.response = response
        self.raise_error = raise_error
        self.calls: list[str] = []

    @property
    def id(self) -> str:
        return "t_mock"

    @property
    def locator(self) -> str:
        return "mock.py:target"

    def __call__(self, message: str) -> str:
        self.calls.append(message)
        if self.raise_error:
            raise RuntimeError("Connection refused")
        return self.response


class MockNoneTarget:
    """Mock target that returns None."""

    @property
    def id(self) -> str:
        return "t_mock_none"

    @property
    def locator(self) -> str:
        return "mock.py:none_target"

    def __call__(self, message: str) -> None:
        return None


class TestPreflightCheck:
    """Test preflight check functionality."""

    def test_preflight_passes_for_working_target(self) -> None:
        """Preflight check passes when target responds."""
        config = SerixSessionConfig(
            target_path="mock.py:target",
            skip_regression=True,  # Skip regression to focus on preflight
        )
        target = MockTarget(response="Hello!")
        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=MockLLMProvider(),
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

        # Run should not raise (preflight succeeds)
        result = workflow.run()
        assert result is not None
        # Target should have been called with "hello" during preflight
        assert "hello" in target.calls

    def test_preflight_raises_for_unreachable_target(self) -> None:
        """Preflight check raises TargetUnreachableError when target fails."""
        config = SerixSessionConfig(
            target_path="mock.py:broken",
            skip_regression=True,
        )
        target = MockTarget(raise_error=True)
        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=MockLLMProvider(),
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

        with pytest.raises(TargetUnreachableError) as exc_info:
            workflow.run()

        assert "Connection refused" in str(exc_info.value)
        assert "mock.py:broken" in str(exc_info.value)

    def test_preflight_raises_for_none_response(self) -> None:
        """Preflight check raises when target returns None."""
        config = SerixSessionConfig(
            target_path="mock.py:none_target",
            skip_regression=True,
        )
        target = MockNoneTarget()
        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=MockLLMProvider(),
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
        )

        with pytest.raises(TargetUnreachableError) as exc_info:
            workflow.run()

        assert "returned None" in str(exc_info.value)

    def test_preflight_emits_progress_event(self) -> None:
        """Preflight check emits PREFLIGHT progress event."""
        config = SerixSessionConfig(
            target_path="mock.py:target",
            skip_regression=True,
        )
        target = MockTarget()
        events: list[ProgressEvent] = []

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=MockLLMProvider(),
            attack_store=MockAttackStore(),
            campaign_store=MockCampaignStore(),
            progress_callback=events.append,
        )

        workflow.run()

        # First event should be PREFLIGHT
        assert len(events) > 0
        assert events[0].phase == ProgressPhase.PREFLIGHT


class TestTargetUnreachableError:
    """Test TargetUnreachableError class."""

    def test_error_message_includes_all_details(self) -> None:
        """Error message includes target_id, locator, and reason."""
        error = TargetUnreachableError(
            target_id="t_abc123",
            locator="agent.py:my_agent",
            reason="Connection refused",
        )

        msg = str(error)
        assert "t_abc123" in msg
        assert "agent.py:my_agent" in msg
        assert "Connection refused" in msg

    def test_error_attributes_accessible(self) -> None:
        """Error attributes are accessible."""
        error = TargetUnreachableError(
            target_id="t_test",
            locator="test.py:fn",
            reason="timeout",
        )

        assert error.target_id == "t_test"
        assert error.locator == "test.py:fn"
        assert error.reason == "timeout"
