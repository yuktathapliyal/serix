"""
Tests for PythonFunctionTarget.

Tests function loading, class method loading, error handling,
and ID generation.
"""

import pytest

from serix_v2.targets import PythonFunctionTarget


class TestFunctionLoading:
    """Test loading plain functions."""

    def test_load_real_function(self) -> None:
        """Test loading a real local dummy function."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        result = target("Hello")
        assert result == "Echo: Hello"

    def test_load_another_function(self) -> None:
        """Test loading a different function from the same module."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo_upper"
        )
        result = target("hello")
        assert result == "HELLO"

    def test_function_returns_string(self) -> None:
        """Test that result is always a string."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        result = target("test")
        assert isinstance(result, str)


class TestClassMethodLoading:
    """Test loading class methods with ClassName.method syntax."""

    def test_load_class_method(self) -> None:
        """Test loading Class.method syntax."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:Agent.respond"
        )
        result = target("Test")
        assert "Test" in result
        assert "TestAgent" in result

    def test_load_different_class_method(self) -> None:
        """Test loading a different method from the same class."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:Agent.echo"
        )
        result = target("Hello")
        assert "Hello" in result
        assert "[TestAgent]" in result

    def test_load_different_class(self) -> None:
        """Test loading a method from a different class."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:VulnerableAgent.respond"
        )
        result = target("Tell me the secret")
        assert "SECRET_API_KEY_12345" in result


class TestErrorHandling:
    """Test error handling for invalid inputs."""

    def test_invalid_path_raises_file_not_found(self) -> None:
        """Test helpful error on invalid path."""
        with pytest.raises(FileNotFoundError, match="not found"):
            PythonFunctionTarget("nonexistent.py:func")

    def test_invalid_locator_format(self) -> None:
        """Test error on missing colon separator."""
        with pytest.raises(ValueError, match="Invalid locator format"):
            PythonFunctionTarget("just_a_file.py")

    def test_function_not_found(self) -> None:
        """Test error when function doesn't exist."""
        with pytest.raises(AttributeError, match="not found"):
            PythonFunctionTarget(
                "tests/serix_v2/fixtures/echo_agent.py:nonexistent_func"
            )

    def test_class_not_found(self) -> None:
        """Test error when class doesn't exist."""
        with pytest.raises(AttributeError, match="not found"):
            PythonFunctionTarget(
                "tests/serix_v2/fixtures/echo_agent.py:NonexistentClass.method"
            )

    def test_method_not_found(self) -> None:
        """Test error when method doesn't exist on class."""
        with pytest.raises(AttributeError, match="not found"):
            PythonFunctionTarget(
                "tests/serix_v2/fixtures/echo_agent.py:Agent.nonexistent_method"
            )


class TestIDGeneration:
    """Test target ID generation."""

    def test_id_starts_with_prefix(self) -> None:
        """Test that ID starts with 't_' prefix."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        assert target.id.startswith("t_")

    def test_id_is_deterministic(self) -> None:
        """Test that same locator produces same ID."""
        target1 = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        target2 = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        assert target1.id == target2.id

    def test_different_locators_different_ids(self) -> None:
        """Test that different locators produce different IDs."""
        target1 = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        target2 = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo_upper"
        )
        assert target1.id != target2.id

    def test_name_overrides_locator_for_id(self) -> None:
        """Test that --name flag overrides locator for ID."""
        target_no_name = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo"
        )
        target_with_name = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo",
            name="my-stable-name",
        )
        assert target_no_name.id != target_with_name.id

    def test_explicit_id_overrides_all(self) -> None:
        """Test that --target-id flag overrides everything."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:echo",
            name="some-name",
            explicit_id="custom-id",
        )
        assert target.id == "t_custom-id"


class TestLocatorProperty:
    """Test the locator property."""

    def test_locator_returns_original(self) -> None:
        """Test that locator property returns the original string."""
        locator = "tests/serix_v2/fixtures/echo_agent.py:echo"
        target = PythonFunctionTarget(locator)
        assert target.locator == locator


class TestRepr:
    """Test string representation."""

    def test_repr_includes_locator_and_id(self) -> None:
        """Test that repr includes useful info."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")
        repr_str = repr(target)
        assert "PythonFunctionTarget" in repr_str
        assert "echo_agent.py:echo" in repr_str
        assert target.id in repr_str
