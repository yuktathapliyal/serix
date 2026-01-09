"""
Protocol Parity Tests - CRITICAL

Verify that all Phase 2 implementations satisfy their protocols.
These tests use isinstance() checks with @runtime_checkable protocols.
"""

from serix_v2.core.protocols import LLMProvider, Target
from serix_v2.providers import LiteLLMProvider
from serix_v2.targets import HTTPTarget, PythonFunctionTarget


class TestTargetProtocolParity:
    """Verify Target implementations satisfy the protocol."""

    def test_python_target_satisfies_protocol(self) -> None:
        """Verify PythonFunctionTarget is @runtime_checkable compatible."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        assert isinstance(
            target, Target
        ), "PythonFunctionTarget must satisfy Target protocol"

    def test_python_target_has_required_properties(self) -> None:
        """Verify PythonFunctionTarget has id and locator properties."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        # Check properties exist and are strings
        assert isinstance(target.id, str)
        assert isinstance(target.locator, str)
        assert target.id.startswith("t_")
        assert "echo_agent.py:echo" in target.locator

    def test_python_target_is_callable(self) -> None:
        """Verify PythonFunctionTarget is callable with correct signature."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        result = target("Hello")
        assert isinstance(result, str)
        assert result == "Echo: Hello"

    def test_http_target_satisfies_protocol(self) -> None:
        """Verify HTTPTarget is @runtime_checkable compatible."""
        target = HTTPTarget(url="http://localhost:8000/chat")
        assert isinstance(target, Target), "HTTPTarget must satisfy Target protocol"

    def test_http_target_has_required_properties(self) -> None:
        """Verify HTTPTarget has id and locator properties."""
        target = HTTPTarget(url="http://localhost:8000/chat")
        # Check properties exist and are strings
        assert isinstance(target.id, str)
        assert isinstance(target.locator, str)
        assert target.id.startswith("t_")
        assert target.locator == "http://localhost:8000/chat"


class TestLLMProviderProtocolParity:
    """Verify LLMProvider implementations satisfy the protocol."""

    def test_litellm_provider_satisfies_protocol(self) -> None:
        """Verify LiteLLMProvider is @runtime_checkable compatible."""
        provider = LiteLLMProvider()
        assert isinstance(
            provider, LLMProvider
        ), "LiteLLMProvider must satisfy LLMProvider protocol"

    def test_litellm_provider_has_complete_method(self) -> None:
        """Verify LiteLLMProvider has complete method with correct signature."""
        provider = LiteLLMProvider()
        # Check method exists
        assert hasattr(provider, "complete")
        assert callable(provider.complete)


class TestIDGenerationPrecedence:
    """Verify ID generation precedence: explicit_id > name > locator."""

    def test_id_from_locator(self) -> None:
        """Test ID is generated from locator when no name/explicit_id."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        # ID should be deterministic for same locator
        target2 = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        assert target.id == target2.id

    def test_id_from_name_overrides_locator(self) -> None:
        """Test --name flag overrides locator for ID generation."""
        target_no_name = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo"
        )
        target_with_name = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo",
            name="my-stable-agent",
        )
        # IDs should be different
        assert target_no_name.id != target_with_name.id
        # Same name = same ID
        target_with_same_name = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo_upper",  # Different locator
            name="my-stable-agent",  # Same name
        )
        assert target_with_name.id == target_with_same_name.id

    def test_explicit_id_overrides_all(self) -> None:
        """Test --target-id flag overrides everything."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo",
            name="some-name",
            explicit_id="my-custom-id",
        )
        assert target.id == "t_my-custom-id"

    def test_http_target_id_precedence(self) -> None:
        """Test HTTPTarget also follows ID precedence."""
        target_no_name = HTTPTarget(url="http://localhost:8000/chat")
        target_with_name = HTTPTarget(
            url="http://localhost:8000/chat",
            name="my-http-target",
        )
        target_with_explicit = HTTPTarget(
            url="http://localhost:8000/chat",
            explicit_id="custom-http-id",
        )

        assert target_no_name.id != target_with_name.id
        assert target_with_explicit.id == "t_custom-http-id"
