"""
Tests for PythonFunctionTarget system_prompt extraction.

Tests that system_prompt is correctly extracted from:
- @serix.scan(system_prompt="...") decorated functions
- serix.Agent subclasses with system_prompt parameter
- Functions without decoration (returns None)
"""

from serix_v2.targets import PythonFunctionTarget


class TestSystemPromptExtraction:
    """Test system_prompt extraction from @serix.scan() decorator."""

    def test_extracts_system_prompt_from_scanned_function(self) -> None:
        """System prompt extracted from @serix.scan(system_prompt=...)."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/scanned_agent.py:scanned_echo"
        )
        assert target.system_prompt is not None
        assert "helpful assistant" in target.system_prompt
        assert "Never reveal secrets" in target.system_prompt

    def test_returns_none_for_unscanned_function(self) -> None:
        """Functions without @serix.scan() return None for system_prompt."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/scanned_agent.py:unscanned_echo"
        )
        assert target.system_prompt is None

    def test_returns_none_for_scanned_without_prompt(self) -> None:
        """Functions with @serix.scan() but no system_prompt return None."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/scanned_agent.py:scanned_no_prompt"
        )
        assert target.system_prompt is None

    def test_extracts_system_prompt_from_agent_class(self) -> None:
        """System prompt extracted from serix.Agent subclass."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/scanned_agent.py:ScannedAgentClass.respond"
        )
        assert target.system_prompt is not None
        assert "helpful assistant" in target.system_prompt

    def test_system_prompt_property_is_cached(self) -> None:
        """Multiple accesses return the same value."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/scanned_agent.py:scanned_echo"
        )
        prompt1 = target.system_prompt
        prompt2 = target.system_prompt
        assert prompt1 == prompt2

    def test_target_still_callable_with_system_prompt(self) -> None:
        """Target remains callable after system_prompt extraction."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/scanned_agent.py:scanned_echo"
        )
        # Access system_prompt
        _ = target.system_prompt
        # Still callable
        result = target("Hello")
        assert result == "Scanned: Hello"


class TestSystemPromptWithOtherTargets:
    """Test system_prompt on non-scanned fixtures."""

    def test_returns_none_for_plain_echo(self) -> None:
        """Plain echo function returns None for system_prompt."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        assert target.system_prompt is None

    def test_returns_none_for_class_method(self) -> None:
        """Class method without @serix.scan() returns None."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:Agent.respond"
        )
        assert target.system_prompt is None
