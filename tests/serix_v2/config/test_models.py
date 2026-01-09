"""
Tests for config/models.py - TOML Pydantic models.

Tests verify that Pydantic models correctly parse TOML-like data structures.
"""

from serix_v2.config.models import (
    TomlAttackConfig,
    TomlConfig,
    TomlFuzzConfig,
    TomlModelsConfig,
    TomlOutputConfig,
    TomlRegressionConfig,
    TomlTargetConfig,
)


class TestTomlTargetConfig:
    """Tests for TomlTargetConfig model."""

    def test_defaults_all_none(self):
        """All fields should default to None."""
        config = TomlTargetConfig()
        assert config.path is None
        assert config.script is None
        assert config.name is None
        assert config.id is None
        assert config.input_field is None
        assert config.output_field is None
        assert config.headers is None
        assert config.headers_file is None

    def test_parses_complete_config(self):
        """Should parse a complete target configuration."""
        config = TomlTargetConfig(
            path="agent.py:main",
            name="my-agent",
            id="custom-id",
            input_field="query",
            output_field="answer",
            headers={"Authorization": "Bearer token"},
            headers_file="headers.json",
        )
        assert config.path == "agent.py:main"
        assert config.name == "my-agent"
        assert config.headers == {"Authorization": "Bearer token"}


class TestTomlAttackConfig:
    """Tests for TomlAttackConfig model."""

    def test_goal_as_string(self):
        """goal can be a single string."""
        config = TomlAttackConfig(goal="reveal secrets")
        assert config.goal == "reveal secrets"

    def test_goal_as_array(self):
        """goal can be an array of strings."""
        config = TomlAttackConfig(goal=["goal1", "goal2"])
        assert config.goal == ["goal1", "goal2"]

    def test_scenarios_as_string(self):
        """scenarios can be a single string."""
        config = TomlAttackConfig(scenarios="jailbreak")
        assert config.scenarios == "jailbreak"

    def test_scenarios_as_array(self):
        """scenarios can be an array of strings."""
        config = TomlAttackConfig(scenarios=["jailbreak", "extraction"])
        assert config.scenarios == ["jailbreak", "extraction"]

    def test_backward_compat_fields(self):
        """Backward compatibility fields should parse correctly."""
        config = TomlAttackConfig(
            max_attempts=10,
            report="report.html",
            stop_on_first=True,
        )
        assert config.max_attempts == 10
        assert config.report == "report.html"
        assert config.stop_on_first is True


class TestTomlFuzzConfig:
    """Tests for TomlFuzzConfig model."""

    def test_latency_bool_true(self):
        """latency=true should parse as boolean True."""
        config = TomlFuzzConfig(latency=True)
        assert config.latency is True

    def test_latency_bool_false(self):
        """latency=false should parse as boolean False."""
        config = TomlFuzzConfig(latency=False)
        assert config.latency is False

    def test_latency_float(self):
        """latency=5.0 should parse as float."""
        config = TomlFuzzConfig(latency=5.0)
        assert config.latency == 5.0

    def test_backward_compat_fields(self):
        """Backward compatibility fields should parse correctly."""
        config = TomlFuzzConfig(
            json_corruption=True,
            mutation_probability=0.5,
            latency_seconds=3.0,
        )
        assert config.json_corruption is True
        assert config.mutation_probability == 0.5
        assert config.latency_seconds == 3.0


class TestTomlConfig:
    """Tests for TomlConfig root model."""

    def test_empty_config(self):
        """Empty config should produce default sub-models."""
        config = TomlConfig()

        # All sections should exist with default values
        assert config.target is not None
        assert config.attack is not None
        assert config.regression is not None
        assert config.output is not None
        assert config.models is not None
        assert config.fuzz is not None

        # Sub-model fields should be None
        assert config.target.path is None
        assert config.attack.goal is None
        assert config.fuzz.latency is None

        # Root-level fields should be None
        assert config.verbose is None
        assert config.yes is None
        assert config.exhaustive is None

    def test_partial_sections(self):
        """Missing sections should use defaults while preserving set values."""
        config = TomlConfig(
            target=TomlTargetConfig(path="agent.py:fn"),
            verbose=True,
        )

        # Provided values should be set
        assert config.target.path == "agent.py:fn"
        assert config.verbose is True

        # Missing sections should use defaults
        assert config.attack.goal is None
        assert config.fuzz.enabled is None
        assert config.exhaustive is None

    def test_full_config(self):
        """Should parse a fully populated configuration."""
        config = TomlConfig(
            target=TomlTargetConfig(path="agent.py:main", name="my-agent"),
            attack=TomlAttackConfig(goal="test", depth=10),
            regression=TomlRegressionConfig(enabled=True),
            output=TomlOutputConfig(report="report.html"),
            models=TomlModelsConfig(attacker="gpt-4"),
            fuzz=TomlFuzzConfig(enabled=True, latency=2.5),
            verbose=True,
            exhaustive=False,
        )

        assert config.target.path == "agent.py:main"
        assert config.attack.depth == 10
        assert config.regression.enabled is True
        assert config.output.report == "report.html"
        assert config.models.attacker == "gpt-4"
        assert config.fuzz.latency == 2.5
        assert config.verbose is True
        assert config.exhaustive is False


class TestTomlModelsConfig:
    """Tests for TomlModelsConfig model."""

    def test_all_model_fields(self):
        """All LLM model override fields should parse correctly."""
        config = TomlModelsConfig(
            attacker="gpt-4o-mini",
            judge="gpt-4o",
            critic="claude-3-sonnet",
            patcher="gpt-4o",
            analyzer="gpt-3.5-turbo",
        )
        assert config.attacker == "gpt-4o-mini"
        assert config.judge == "gpt-4o"
        assert config.critic == "claude-3-sonnet"
        assert config.patcher == "gpt-4o"
        assert config.analyzer == "gpt-3.5-turbo"


class TestTomlOutputConfig:
    """Tests for TomlOutputConfig model."""

    def test_output_fields(self):
        """All output fields should parse correctly."""
        config = TomlOutputConfig(
            report="output/report.html",
            no_report=False,
            dry_run=True,
            github=True,
        )
        assert config.report == "output/report.html"
        assert config.no_report is False
        assert config.dry_run is True
        assert config.github is True


class TestTomlRegressionConfig:
    """Tests for TomlRegressionConfig model."""

    def test_regression_fields(self):
        """Regression fields should parse correctly."""
        config = TomlRegressionConfig(
            enabled=False,
            skip_mitigated=True,
        )
        assert config.enabled is False
        assert config.skip_mitigated is True
