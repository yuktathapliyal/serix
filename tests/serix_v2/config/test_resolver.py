"""
Tests for config/resolver.py - Configuration resolution logic.

Tests verify the priority chain: CLI > Environment Variables > TOML > Defaults
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from serix_v2.config.models import (
    TomlAttackConfig,
    TomlConfig,
    TomlFuzzConfig,
    TomlRegressionConfig,
    TomlTargetConfig,
)
from serix_v2.config.resolver import (
    CLIOverrides,
    load_env_overrides,
    resolve_config,
    resolve_exhaustive,
    resolve_fuzz_latency,
    resolve_scenarios,
    resolve_skip_regression,
)
from serix_v2.core import constants
from serix_v2.core.contracts import AttackMode
from serix_v2.core.errors import ConfigValidationError


class TestCLIOverridesToml:
    """Tests for CLI > TOML priority."""

    def test_cli_overrides_toml_target_path(self, tmp_path: Path):
        """CLI target_path should override TOML."""
        cli = CLIOverrides(target_path="cli-agent.py:fn")
        toml = TomlConfig(target=TomlTargetConfig(path="toml-agent.py:fn"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.target_path == "cli-agent.py:fn"

    def test_cli_overrides_toml_depth(self, tmp_path: Path):
        """CLI depth should override TOML."""
        cli = CLIOverrides(target_path="agent.py:fn", depth=20)
        toml = TomlConfig(attack=TomlAttackConfig(depth=5))

        config = resolve_config(cli, toml, tmp_path)

        assert config.depth == 20

    def test_cli_overrides_toml_verbose(self, tmp_path: Path):
        """CLI verbose should override TOML."""
        cli = CLIOverrides(target_path="agent.py:fn", verbose=True)
        toml = TomlConfig(verbose=False)

        config = resolve_config(cli, toml, tmp_path)

        assert config.verbose is True


class TestEnvOverrides:
    """Tests for Environment Variable > TOML priority."""

    def test_env_overrides_toml_depth(self, tmp_path: Path):
        """SERIX_DEPTH should override TOML depth."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(depth=5))

        with patch.dict(os.environ, {"SERIX_DEPTH": "15"}):
            config = resolve_config(cli, toml, tmp_path)

        assert config.depth == 15

    def test_env_serix_verbose_truthy(self, tmp_path: Path):
        """SERIX_VERBOSE=1 should set verbose=True."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(verbose=False)

        with patch.dict(os.environ, {"SERIX_VERBOSE": "1"}):
            config = resolve_config(cli, toml, tmp_path)

        assert config.verbose is True

    def test_env_serix_dry_run(self, tmp_path: Path):
        """SERIX_DRY_RUN=true should set dry_run=True."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig()

        with patch.dict(os.environ, {"SERIX_DRY_RUN": "true"}):
            config = resolve_config(cli, toml, tmp_path)

        assert config.dry_run is True

    def test_env_serix_judge_model(self, tmp_path: Path):
        """SERIX_JUDGE_MODEL should set judge_model."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig()

        with patch.dict(os.environ, {"SERIX_JUDGE_MODEL": "gpt-4o-mini"}):
            config = resolve_config(cli, toml, tmp_path)

        assert config.judge_model == "gpt-4o-mini"

    def test_cli_overrides_env(self, tmp_path: Path):
        """CLI should override env var."""
        cli = CLIOverrides(target_path="agent.py:fn", depth=25)
        toml = TomlConfig()

        with patch.dict(os.environ, {"SERIX_DEPTH": "10"}):
            config = resolve_config(cli, toml, tmp_path)

        assert config.depth == 25


class TestTomlOverridesDefaults:
    """Tests for TOML > Defaults priority."""

    def test_toml_overrides_default_depth(self, tmp_path: Path):
        """TOML depth should override default."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(depth=8))

        config = resolve_config(cli, toml, tmp_path)

        assert config.depth == 8

    def test_default_used_when_all_none(self, tmp_path: Path):
        """Default should be used when CLI, env, and TOML are None."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig()

        config = resolve_config(cli, toml, tmp_path)

        assert config.depth == constants.DEFAULT_DEPTH
        assert config.attacker_model == constants.DEFAULT_ATTACKER_MODEL


class TestGoalResolution:
    """Tests for goal resolution (first non-empty wins, NO merging)."""

    def test_cli_goals_wins_over_config(self, tmp_path: Path):
        """CLI --goal should beat config goals."""
        cli = CLIOverrides(target_path="agent.py:fn", goals=["cli-goal"])
        toml = TomlConfig(attack=TomlAttackConfig(goal="toml-goal"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.goals == ["cli-goal"]

    def test_cli_goals_file_wins(self, tmp_path: Path):
        """CLI --goals-file should beat everything."""
        goals_file = tmp_path / "cli-goals.txt"
        goals_file.write_text("goal-from-cli-file\n")

        cli = CLIOverrides(
            target_path="agent.py:fn",
            goals_file=str(goals_file),
            goals=["should-be-ignored"],
        )
        toml = TomlConfig(attack=TomlAttackConfig(goal="toml-goal"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.goals == ["goal-from-cli-file"]

    def test_toml_goals_file(self, tmp_path: Path):
        """Config goals_file should work."""
        goals_file = tmp_path / "goals.txt"
        goals_file.write_text("goal1\ngoal2\n")

        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(goals_file="goals.txt"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.goals == ["goal1", "goal2"]

    def test_toml_goals_array(self, tmp_path: Path):
        """Config goals array should work."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(goals=["g1", "g2", "g3"]))

        config = resolve_config(cli, toml, tmp_path)

        assert config.goals == ["g1", "g2", "g3"]

    def test_toml_goal_string_becomes_list(self, tmp_path: Path):
        """Config goal as string should become a list."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(goal="single-goal"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.goals == ["single-goal"]

    def test_toml_goal_array(self, tmp_path: Path):
        """Config goal as array should work."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(goal=["g1", "g2"]))

        config = resolve_config(cli, toml, tmp_path)

        assert config.goals == ["g1", "g2"]

    def test_default_goal_fallback(self, tmp_path: Path):
        """Default goal should be used when all sources empty."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig()

        config = resolve_config(cli, toml, tmp_path)

        assert config.goals == [constants.DEFAULT_GOAL]

    def test_goals_not_merged(self, tmp_path: Path):
        """Goals should NOT merge from multiple sources."""
        cli = CLIOverrides(target_path="agent.py:fn", goals=["cli-goal"])
        toml = TomlConfig(attack=TomlAttackConfig(goals=["toml1", "toml2"]))

        config = resolve_config(cli, toml, tmp_path)

        # Should ONLY have CLI goal, not merged
        assert config.goals == ["cli-goal"]
        assert "toml1" not in config.goals


class TestInversionLogic:
    """Tests for field inversion (regression.enabled → skip_regression)."""

    def test_regression_enabled_true_means_skip_false(self, tmp_path: Path):
        """enabled=true should set skip_regression=False."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(regression=TomlRegressionConfig(enabled=True))

        config = resolve_config(cli, toml, tmp_path)

        assert config.skip_regression is False

    def test_regression_enabled_false_means_skip_true(self, tmp_path: Path):
        """enabled=false should set skip_regression=True."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(regression=TomlRegressionConfig(enabled=False))

        config = resolve_config(cli, toml, tmp_path)

        assert config.skip_regression is True

    def test_cli_skip_regression_overrides_config(self, tmp_path: Path):
        """CLI --skip-regression should override config."""
        cli = CLIOverrides(target_path="agent.py:fn", skip_regression=True)
        toml = TomlConfig(regression=TomlRegressionConfig(enabled=True))

        config = resolve_config(cli, toml, tmp_path)

        assert config.skip_regression is True


class TestTypeCoercion:
    """Tests for type coercion (scenarios string→list, latency bool→float)."""

    def test_scenarios_string_to_list(self, tmp_path: Path):
        """Scenarios string should become a list."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(scenarios="jailbreak"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.scenarios == ["jailbreak"]

    def test_scenarios_all_string(self, tmp_path: Path):
        """'all' scenarios string should work."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(scenarios="all"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.scenarios == ["all"]

    def test_fuzz_latency_true_uses_default(self, tmp_path: Path):
        """latency=true should use DEFAULT_FUZZ_LATENCY."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(fuzz=TomlFuzzConfig(latency=True))

        config = resolve_config(cli, toml, tmp_path)

        assert config.fuzz_latency == constants.DEFAULT_FUZZ_LATENCY

    def test_fuzz_latency_true_with_latency_seconds(self, tmp_path: Path):
        """latency=true with latency_seconds should use latency_seconds."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(fuzz=TomlFuzzConfig(latency=True, latency_seconds=3.0))

        config = resolve_config(cli, toml, tmp_path)

        assert config.fuzz_latency == 3.0

    def test_fuzz_latency_float_used_directly(self, tmp_path: Path):
        """latency=5.0 should be used directly."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(fuzz=TomlFuzzConfig(latency=5.0))

        config = resolve_config(cli, toml, tmp_path)

        assert config.fuzz_latency == 5.0

    def test_fuzz_latency_false_means_none(self, tmp_path: Path):
        """latency=false should set fuzz_latency=None."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(fuzz=TomlFuzzConfig(latency=False))

        config = resolve_config(cli, toml, tmp_path)

        assert config.fuzz_latency is None


class TestBackwardCompatibility:
    """Tests for backward compatibility field mappings."""

    def test_target_script_fallback(self, tmp_path: Path):
        """Uses script if path missing (deprecated)."""
        cli = CLIOverrides()
        toml = TomlConfig(target=TomlTargetConfig(script="old-agent.py:fn"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.target_path == "old-agent.py:fn"

    def test_attack_max_attempts_fallback(self, tmp_path: Path):
        """Uses max_attempts for depth (deprecated)."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(max_attempts=12))

        config = resolve_config(cli, toml, tmp_path)

        assert config.depth == 12

    def test_attack_report_fallback(self, tmp_path: Path):
        """Uses [attack].report if [output].report missing."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(report="old-report.html"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.report_path == "old-report.html"

    def test_fuzz_mutation_probability_fallback(self, tmp_path: Path):
        """Uses mutation_probability for probability (deprecated)."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(fuzz=TomlFuzzConfig(mutation_probability=0.5))

        config = resolve_config(cli, toml, tmp_path)

        assert config.fuzz_probability == 0.5

    def test_fuzz_json_corruption_fallback(self, tmp_path: Path):
        """Uses json_corruption for fuzz_json (deprecated)."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(fuzz=TomlFuzzConfig(json_corruption=True))

        config = resolve_config(cli, toml, tmp_path)

        assert config.fuzz_json is True

    def test_stop_on_first_fallback(self, tmp_path: Path):
        """Uses stop_on_first inverted to exhaustive (deprecated)."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(stop_on_first=True))

        config = resolve_config(cli, toml, tmp_path)

        # stop_on_first=true means exhaustive=false
        assert config.exhaustive is False

    def test_stop_on_first_inverted(self, tmp_path: Path):
        """stop_on_first=false means exhaustive=true."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(attack=TomlAttackConfig(stop_on_first=False))

        config = resolve_config(cli, toml, tmp_path)

        assert config.exhaustive is True


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_empty_config_uses_all_defaults(self, tmp_path: Path):
        """Empty config should use all defaults except required fields."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig()

        config = resolve_config(cli, toml, tmp_path)

        assert config.depth == constants.DEFAULT_DEPTH
        assert config.attacker_model == constants.DEFAULT_ATTACKER_MODEL
        assert config.judge_model == constants.DEFAULT_JUDGE_MODEL
        assert config.mode == AttackMode.ADAPTIVE
        assert config.scenarios == constants.DEFAULT_SCENARIOS

    def test_required_target_path_validation(self, tmp_path: Path):
        """Missing target_path should raise ConfigValidationError."""
        cli = CLIOverrides()  # No target_path
        toml = TomlConfig()

        with pytest.raises(ConfigValidationError) as exc_info:
            resolve_config(cli, toml, tmp_path)

        assert exc_info.value.field == "target_path"

    def test_mode_from_string(self, tmp_path: Path):
        """Mode string should be converted to AttackMode enum."""
        cli = CLIOverrides(target_path="agent.py:fn", mode="static")
        toml = TomlConfig()

        config = resolve_config(cli, toml, tmp_path)

        assert config.mode == AttackMode.STATIC

    def test_headers_from_file(self, tmp_path: Path):
        """Headers file should be read and parsed."""
        headers_file = tmp_path / "headers.json"
        headers_file.write_text('{"Authorization": "Bearer token"}')

        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(target=TomlTargetConfig(headers_file="headers.json"))

        config = resolve_config(cli, toml, tmp_path)

        assert config.headers == {"Authorization": "Bearer token"}


class TestLoadEnvOverrides:
    """Tests for load_env_overrides() function."""

    def test_loads_depth(self):
        """Should load SERIX_DEPTH as int."""
        with patch.dict(os.environ, {"SERIX_DEPTH": "10"}):
            result = load_env_overrides()

        assert result["depth"] == 10

    def test_loads_verbose_bool(self):
        """Should load SERIX_VERBOSE as bool."""
        with patch.dict(os.environ, {"SERIX_VERBOSE": "true"}):
            result = load_env_overrides()

        assert result["verbose"] is True

    def test_loads_fuzz_probability_float(self):
        """Should load SERIX_FUZZ_PROBABILITY as float."""
        with patch.dict(os.environ, {"SERIX_FUZZ_PROBABILITY": "0.75"}):
            result = load_env_overrides()

        assert result["fuzz_probability"] == 0.75

    def test_ignores_invalid_values(self):
        """Should skip invalid env values silently."""
        with patch.dict(os.environ, {"SERIX_DEPTH": "not-a-number"}):
            result = load_env_overrides()

        assert "depth" not in result


class TestResolveFunctions:
    """Tests for individual resolve_* helper functions."""

    def test_resolve_scenarios_cli_wins(self):
        """CLI scenarios should win."""
        result = resolve_scenarios(["cli-scenario"], "toml-scenario")
        assert result == ["cli-scenario"]

    def test_resolve_scenarios_string_to_list(self):
        """String scenarios should become list."""
        result = resolve_scenarios(None, "single")
        assert result == ["single"]

    def test_resolve_scenarios_default(self):
        """Default scenarios when all None."""
        result = resolve_scenarios(None, None)
        assert result == constants.DEFAULT_SCENARIOS

    def test_resolve_fuzz_latency_cli_wins(self):
        """CLI fuzz latency should win."""
        result = resolve_fuzz_latency(2.5, True, 5.0)
        assert result == 2.5

    def test_resolve_skip_regression_cli_wins(self):
        """CLI skip_regression should win."""
        result = resolve_skip_regression(True, True, True)
        assert result is True  # CLI says skip

    def test_resolve_exhaustive_cli_wins(self):
        """CLI exhaustive should win."""
        result = resolve_exhaustive(True, False, True)
        assert result is True
