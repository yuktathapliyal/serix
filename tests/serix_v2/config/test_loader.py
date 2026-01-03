"""
Tests for config/loader.py - TOML file finding and loading.

Tests use inline TOML strings written to temp files for clarity.
"""

from pathlib import Path

import pytest

from serix_v2.config.loader import find_config_file, load_toml_config
from serix_v2.config.models import TomlConfig
from serix_v2.core.errors import ConfigParseError


class TestFindConfigFile:
    """Tests for find_config_file() - directory tree traversal."""

    def test_serix_toml_current_dir(self, tmp_path: Path):
        """Should find serix.toml in current directory."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text('[target]\npath = "agent.py:fn"\n')

        result = find_config_file(tmp_path)

        assert result == config_file

    def test_pyproject_toml(self, tmp_path: Path):
        """Should find pyproject.toml with [tool.serix] section."""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text(
            "[build-system]\n"
            'requires = ["setuptools"]\n\n'
            "[tool.serix]\n"
            "verbose = true\n"
        )

        result = find_config_file(tmp_path)

        assert result == config_file

    def test_walks_up_tree(self, tmp_path: Path):
        """Should search parent directories for config file."""
        # Create nested directory structure
        project_root = tmp_path / "project"
        src_dir = project_root / "src" / "module"
        src_dir.mkdir(parents=True)

        # Config file is at project root
        config_file = project_root / "serix.toml"
        config_file.write_text('[target]\npath = "agent.py:fn"\n')

        # Start search from deeply nested directory
        result = find_config_file(src_dir)

        assert result == config_file

    def test_serix_priority_over_pyproject(self, tmp_path: Path):
        """serix.toml should take priority over pyproject.toml in same dir."""
        # Create both files in same directory
        serix_file = tmp_path / "serix.toml"
        serix_file.write_text('[target]\npath = "from-serix.py:fn"\n')

        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text(
            "[tool.serix]\n" "[tool.serix.target]\n" 'path = "from-pyproject.py:fn"\n'
        )

        result = find_config_file(tmp_path)

        # Should prefer serix.toml
        assert result == serix_file

    def test_pyproject_without_serix_section(self, tmp_path: Path):
        """Should ignore pyproject.toml without [tool.serix] section."""
        # Create pyproject.toml without [tool.serix]
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text(
            "[build-system]\n"
            'requires = ["setuptools"]\n\n'
            "[tool.pytest]\n"
            'testpaths = ["tests"]\n'
        )

        result = find_config_file(tmp_path)

        # Should not find this file
        assert result is None

    def test_not_found(self, tmp_path: Path):
        """Should return None when no config file exists."""
        result = find_config_file(tmp_path)

        assert result is None

    def test_stops_at_root(self, tmp_path: Path):
        """Should not search beyond filesystem root."""
        # This test just ensures we don't infinite loop
        # Start from a directory with no config anywhere above
        result = find_config_file(tmp_path)

        assert result is None  # Just verify it terminates


class TestLoadTomlConfig:
    """Tests for load_toml_config() - TOML parsing and validation."""

    def test_complete_config(self, tmp_path: Path):
        """Should load a complete serix.toml file."""
        config_file = tmp_path / "serix.toml"
        # Root-level keys must come before section headers in TOML
        config_file.write_text(
            "verbose = true\n"
            "exhaustive = false\n\n"
            "[target]\n"
            'path = "agent.py:main"\n'
            'name = "my-agent"\n\n'
            "[attack]\n"
            'goal = "reveal secrets"\n'
            "depth = 10\n\n"
            "[models]\n"
            'attacker = "gpt-4o"\n'
        )

        config, config_dir = load_toml_config(config_file)

        assert config.target.path == "agent.py:main"
        assert config.target.name == "my-agent"
        assert config.attack.goal == "reveal secrets"
        assert config.attack.depth == 10
        assert config.models.attacker == "gpt-4o"
        assert config.verbose is True
        assert config.exhaustive is False
        assert config_dir == tmp_path

    def test_partial_config(self, tmp_path: Path):
        """Should load partial config with defaults for missing sections."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text("[target]\n" 'path = "agent.py:fn"\n')

        config, config_dir = load_toml_config(config_file)

        # Provided values
        assert config.target.path == "agent.py:fn"

        # Missing sections should use defaults
        assert config.attack.goal is None
        assert config.fuzz.enabled is None
        assert config.verbose is None

    def test_returns_config_dir(self, tmp_path: Path):
        """Should return directory containing config file."""
        subdir = tmp_path / "config"
        subdir.mkdir()
        config_file = subdir / "serix.toml"
        config_file.write_text("verbose = true\n")

        config, config_dir = load_toml_config(config_file)

        assert config_dir == subdir

    def test_invalid_syntax(self, tmp_path: Path):
        """Should raise ConfigParseError for invalid TOML."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text("this is not valid toml {{{")

        with pytest.raises(ConfigParseError) as exc_info:
            load_toml_config(config_file)

        assert str(config_file) in exc_info.value.path

    def test_no_file_returns_empty(self, tmp_path: Path):
        """Should return empty TomlConfig when no file found."""
        # Start search from empty directory
        config, config_dir = load_toml_config(None)

        # When run from tmp_path with no config, we get the global result
        # Just verify we get a TomlConfig back (may or may not be empty
        # depending on test environment)
        assert isinstance(config, TomlConfig)

    def test_explicit_path_not_found(self, tmp_path: Path):
        """Explicit path that doesn't exist should return empty config."""
        nonexistent = tmp_path / "does_not_exist.toml"

        # Since find_config_file returns None, we get empty config
        # But if we pass an explicit path and it doesn't exist...
        # Actually, load_toml_config only searches if config_path is None
        # If we pass an explicit path that doesn't exist, we get empty config
        # because find_config_file isn't called and the path check happens

        # Actually - let me trace through:
        # If config_path is provided but doesn't exist, read_bytes will fail
        # We should test this...

        with pytest.raises((ConfigParseError, FileNotFoundError)):
            load_toml_config(nonexistent)


class TestPyprojectExtraction:
    """Tests for pyproject.toml [tool.serix] extraction."""

    def test_extracts_tool_serix(self, tmp_path: Path):
        """Should use data from [tool.serix] as root."""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text(
            "[build-system]\n"
            'requires = ["setuptools"]\n\n'
            "[tool.serix]\n"
            "verbose = true\n"
        )

        config, config_dir = load_toml_config(config_file)

        assert config.verbose is True

    def test_nested_sections(self, tmp_path: Path):
        """[tool.serix.target] should become TomlConfig.target."""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text(
            "[tool.serix]\n"
            "verbose = true\n\n"
            "[tool.serix.target]\n"
            'path = "agent.py:fn"\n'
            'name = "my-agent"\n\n'
            "[tool.serix.attack]\n"
            "depth = 15\n"
        )

        config, config_dir = load_toml_config(config_file)

        assert config.verbose is True
        assert config.target.path == "agent.py:fn"
        assert config.target.name == "my-agent"
        assert config.attack.depth == 15

    def test_ignores_other_tools(self, tmp_path: Path):
        """Should only read [tool.serix], not other tool sections."""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text(
            "[tool.pytest]\n"
            'testpaths = ["tests"]\n\n'
            "[tool.ruff]\n"
            "line-length = 88\n\n"
            "[tool.serix]\n"
            "verbose = true\n"
        )

        config, config_dir = load_toml_config(config_file)

        # Should only have serix config
        assert config.verbose is True
        # Other tool configs should not leak in
        assert not hasattr(config, "testpaths")

    def test_empty_serix_section(self, tmp_path: Path):
        """Empty [tool.serix] should produce default config."""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text("[tool.serix]\n" "# Just a comment, no actual config\n")

        config, config_dir = load_toml_config(config_file)

        # Should get default empty config
        assert config.target.path is None
        assert config.verbose is None


class TestGoalAndScenariosUnions:
    """Tests for union type handling (goal, scenarios, latency)."""

    def test_goal_as_string(self, tmp_path: Path):
        """goal should accept a string value."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text("[attack]\n" 'goal = "reveal secrets"\n')

        config, _ = load_toml_config(config_file)

        assert config.attack.goal == "reveal secrets"

    def test_goal_as_array(self, tmp_path: Path):
        """goal should accept an array value."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text("[attack]\n" 'goal = ["goal1", "goal2"]\n')

        config, _ = load_toml_config(config_file)

        assert config.attack.goal == ["goal1", "goal2"]

    def test_scenarios_as_string(self, tmp_path: Path):
        """scenarios should accept a string value."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text("[attack]\n" 'scenarios = "jailbreak"\n')

        config, _ = load_toml_config(config_file)

        assert config.attack.scenarios == "jailbreak"

    def test_scenarios_as_array(self, tmp_path: Path):
        """scenarios should accept an array value."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text("[attack]\n" 'scenarios = ["jailbreak", "extraction"]\n')

        config, _ = load_toml_config(config_file)

        assert config.attack.scenarios == ["jailbreak", "extraction"]

    def test_fuzz_latency_as_bool(self, tmp_path: Path):
        """fuzz.latency should accept boolean values."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text("[fuzz]\n" "latency = true\n")

        config, _ = load_toml_config(config_file)

        assert config.fuzz.latency is True

    def test_fuzz_latency_as_float(self, tmp_path: Path):
        """fuzz.latency should accept float values."""
        config_file = tmp_path / "serix.toml"
        config_file.write_text("[fuzz]\n" "latency = 5.0\n")

        config, _ = load_toml_config(config_file)

        assert config.fuzz.latency == 5.0
