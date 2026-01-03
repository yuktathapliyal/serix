"""
Tests for config/utils.py - IO helper functions.

Tests verify path resolution, file reading, and environment variable parsing.
"""

from pathlib import Path

import pytest

from serix_v2.config.utils import (
    parse_env_bool,
    parse_env_value,
    read_goals_file,
    read_headers_file,
    resolve_path,
)
from serix_v2.core.errors import ConfigValidationError


class TestResolvePath:
    """Tests for resolve_path() - critical for config file path handling."""

    def test_relative_path(self, tmp_path: Path):
        """Relative path should be resolved against config_dir."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        result = resolve_path("goals.txt", config_dir)

        assert result == config_dir / "goals.txt"
        assert result.is_absolute()

    def test_absolute_path(self, tmp_path: Path):
        """Absolute paths should remain unchanged."""
        config_dir = tmp_path / "config"
        absolute_path = tmp_path / "elsewhere" / "goals.txt"

        result = resolve_path(str(absolute_path), config_dir)

        assert result == absolute_path

    def test_dot_relative(self, tmp_path: Path):
        """./relative paths should resolve correctly."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        result = resolve_path("./goals.txt", config_dir)

        # After .resolve(), the path should be normalized
        assert result.name == "goals.txt"
        assert config_dir in result.parents or result.parent == config_dir

    def test_parent_relative(self, tmp_path: Path):
        """../relative paths should resolve correctly."""
        config_dir = tmp_path / "config" / "subdir"
        config_dir.mkdir(parents=True)

        result = resolve_path("../goals.txt", config_dir)

        # Should resolve to tmp_path/config/goals.txt
        expected = (config_dir / ".." / "goals.txt").resolve()
        assert result == expected

    def test_nested_relative(self, tmp_path: Path):
        """Nested relative paths should resolve correctly."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        result = resolve_path("subdir/goals.txt", config_dir)

        assert result == config_dir / "subdir" / "goals.txt"

    def test_pathlib_path_input(self, tmp_path: Path):
        """Should accept Path objects, not just strings."""
        config_dir = tmp_path / "config"

        result = resolve_path(Path("goals.txt"), config_dir)

        assert result == config_dir / "goals.txt"


class TestReadGoalsFile:
    """Tests for read_goals_file() - reading goals from text files."""

    def test_simple_file(self, tmp_path: Path):
        """Should read one goal per line."""
        goals_file = tmp_path / "goals.txt"
        goals_file.write_text("reveal secrets\nbypass safety\n")

        result = read_goals_file(goals_file)

        assert result == ["reveal secrets", "bypass safety"]

    def test_with_comments(self, tmp_path: Path):
        """Lines starting with # should be stripped."""
        goals_file = tmp_path / "goals.txt"
        goals_file.write_text(
            "# This is a comment\n"
            "reveal secrets\n"
            "# Another comment\n"
            "bypass safety\n"
        )

        result = read_goals_file(goals_file)

        assert result == ["reveal secrets", "bypass safety"]

    def test_with_blank_lines(self, tmp_path: Path):
        """Blank lines should be ignored."""
        goals_file = tmp_path / "goals.txt"
        goals_file.write_text(
            "reveal secrets\n" "\n" "bypass safety\n" "\n" "\n" "extract API keys\n"
        )

        result = read_goals_file(goals_file)

        assert result == ["reveal secrets", "bypass safety", "extract API keys"]

    def test_strips_whitespace(self, tmp_path: Path):
        """Leading/trailing whitespace should be trimmed."""
        goals_file = tmp_path / "goals.txt"
        goals_file.write_text(
            "  reveal secrets  \n" "\tbypass safety\t\n" "   extract keys   \n"
        )

        result = read_goals_file(goals_file)

        assert result == ["reveal secrets", "bypass safety", "extract keys"]

    def test_not_found(self, tmp_path: Path):
        """Should raise ConfigValidationError if file not found."""
        nonexistent = tmp_path / "does_not_exist.txt"

        with pytest.raises(ConfigValidationError) as exc_info:
            read_goals_file(nonexistent)

        assert exc_info.value.field == "goals_file"
        assert "not found" in exc_info.value.message.lower()

    def test_empty_file(self, tmp_path: Path):
        """Should raise ConfigValidationError if file is empty."""
        goals_file = tmp_path / "goals.txt"
        goals_file.write_text("")

        with pytest.raises(ConfigValidationError) as exc_info:
            read_goals_file(goals_file)

        assert exc_info.value.field == "goals_file"
        assert "empty" in exc_info.value.message.lower()

    def test_only_comments(self, tmp_path: Path):
        """Should raise ConfigValidationError if file has only comments."""
        goals_file = tmp_path / "goals.txt"
        goals_file.write_text("# Only comments\n# No actual goals\n")

        with pytest.raises(ConfigValidationError) as exc_info:
            read_goals_file(goals_file)

        assert exc_info.value.field == "goals_file"
        assert "empty" in exc_info.value.message.lower()


class TestReadHeadersFile:
    """Tests for read_headers_file() - reading HTTP headers from JSON."""

    def test_valid_json(self, tmp_path: Path):
        """Should parse valid JSON object correctly."""
        headers_file = tmp_path / "headers.json"
        headers_file.write_text(
            '{"Authorization": "Bearer token", "X-Custom": "value"}'
        )

        result = read_headers_file(headers_file)

        assert result == {"Authorization": "Bearer token", "X-Custom": "value"}

    def test_not_found(self, tmp_path: Path):
        """Should raise ConfigValidationError if file not found."""
        nonexistent = tmp_path / "does_not_exist.json"

        with pytest.raises(ConfigValidationError) as exc_info:
            read_headers_file(nonexistent)

        assert exc_info.value.field == "headers_file"
        assert "not found" in exc_info.value.message.lower()

    def test_invalid_json(self, tmp_path: Path):
        """Should raise ConfigValidationError for malformed JSON."""
        headers_file = tmp_path / "headers.json"
        headers_file.write_text("{invalid json}")

        with pytest.raises(ConfigValidationError) as exc_info:
            read_headers_file(headers_file)

        assert exc_info.value.field == "headers_file"
        assert "invalid json" in exc_info.value.message.lower()

    def test_non_object_json(self, tmp_path: Path):
        """Should raise ConfigValidationError if JSON is not an object."""
        headers_file = tmp_path / "headers.json"
        headers_file.write_text('["array", "not", "object"]')

        with pytest.raises(ConfigValidationError) as exc_info:
            read_headers_file(headers_file)

        assert exc_info.value.field == "headers_file"
        assert "object" in exc_info.value.message.lower()

    def test_non_string_value(self, tmp_path: Path):
        """Should raise ConfigValidationError if header value is not a string."""
        headers_file = tmp_path / "headers.json"
        headers_file.write_text('{"Count": 42}')

        with pytest.raises(ConfigValidationError) as exc_info:
            read_headers_file(headers_file)

        assert exc_info.value.field == "headers_file"
        assert "string" in exc_info.value.message.lower()


class TestParseEnvBool:
    """Tests for parse_env_bool() - boolean parsing from env vars."""

    @pytest.mark.parametrize(
        "value", ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON"]
    )
    def test_truthy_values(self, value: str):
        """Truthy strings should return True."""
        assert parse_env_bool(value) is True

    @pytest.mark.parametrize(
        "value", ["0", "false", "False", "FALSE", "no", "NO", "off", "OFF", ""]
    )
    def test_falsy_values(self, value: str):
        """Falsy strings should return False."""
        assert parse_env_bool(value) is False

    def test_whitespace_handling(self):
        """Surrounding whitespace should be ignored."""
        assert parse_env_bool("  true  ") is True
        assert parse_env_bool("\tfalse\t") is False

    def test_invalid_value(self):
        """Unrecognized values should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            parse_env_bool("maybe")

        assert "maybe" in str(exc_info.value)


class TestParseEnvValue:
    """Tests for parse_env_value() - typed parsing from env vars."""

    def test_string_passthrough(self):
        """Strings should pass through unchanged."""
        assert parse_env_value("hello world", str) == "hello world"

    def test_int_parsing(self):
        """Integers should be parsed correctly."""
        assert parse_env_value("10", int) == 10
        assert parse_env_value("-5", int) == -5
        assert parse_env_value("0", int) == 0

    def test_int_invalid(self):
        """Invalid integers should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            parse_env_value("not_a_number", int)

        assert "not_a_number" in str(exc_info.value)

    def test_float_parsing(self):
        """Floats should be parsed correctly."""
        assert parse_env_value("0.5", float) == 0.5
        assert parse_env_value("3.14", float) == 3.14
        assert parse_env_value("-1.5", float) == -1.5
        assert parse_env_value("10", float) == 10.0

    def test_float_invalid(self):
        """Invalid floats should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            parse_env_value("not_a_float", float)

        assert "not_a_float" in str(exc_info.value)

    def test_bool_parsing(self):
        """Booleans should be parsed correctly."""
        assert parse_env_value("true", bool) is True
        assert parse_env_value("1", bool) is True
        assert parse_env_value("false", bool) is False
        assert parse_env_value("0", bool) is False

    def test_unsupported_type(self):
        """Unsupported types should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            parse_env_value("value", list)

        assert "Unsupported" in str(exc_info.value)
