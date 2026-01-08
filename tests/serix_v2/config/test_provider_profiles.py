"""
Tests for multi-provider profiles (Phase 13).

Tests cover:
- Provider detection from environment
- Profile model resolution
- Config cascade with provider profiles
- Mixed provider warnings
"""

import os
from unittest.mock import patch

import pytest

from serix_v2.config.models import TomlConfig
from serix_v2.config.resolver import CLIOverrides, resolve_config
from serix_v2.core.constants import (
    DEFAULT_PROVIDER,
    PROVIDER_ENV_VARS,
    PROVIDER_PROFILES,
    SUPPORTED_PROVIDERS,
    detect_provider,
    get_profile_models,
    infer_provider_from_model,
)


class TestProviderConstants:
    """Test provider profile constants and helpers."""

    def test_supported_providers_includes_big_three(self) -> None:
        """All three major providers are supported."""
        assert "openai" in SUPPORTED_PROVIDERS
        assert "anthropic" in SUPPORTED_PROVIDERS
        assert "google" in SUPPORTED_PROVIDERS

    def test_default_provider_is_openai(self) -> None:
        """OpenAI is the default provider (backward compatible)."""
        assert DEFAULT_PROVIDER == "openai"

    def test_all_profiles_have_all_roles(self) -> None:
        """Every provider profile has all 5 model roles."""
        required_roles = {"attacker", "critic", "analyzer", "judge", "patcher"}

        for provider, profile in PROVIDER_PROFILES.items():
            assert (
                set(profile.keys()) == required_roles
            ), f"Provider {provider} missing roles"

    def test_provider_env_vars_mapping(self) -> None:
        """Environment variable names are correct for each provider."""
        assert PROVIDER_ENV_VARS["openai"] == "OPENAI_API_KEY"
        assert PROVIDER_ENV_VARS["anthropic"] == "ANTHROPIC_API_KEY"
        assert PROVIDER_ENV_VARS["google"] == "GOOGLE_API_KEY"


class TestDetectProvider:
    """Test automatic provider detection from environment."""

    def test_detect_provider_openai_key(self) -> None:
        """Returns 'openai' when OPENAI_API_KEY is set."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            assert detect_provider() == "openai"

    def test_detect_provider_anthropic_key(self) -> None:
        """Returns 'anthropic' when only ANTHROPIC_API_KEY is set."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=True):
            assert detect_provider() == "anthropic"

    def test_detect_provider_google_key(self) -> None:
        """Returns 'google' when only GOOGLE_API_KEY is set."""
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}, clear=True):
            assert detect_provider() == "google"

    def test_detect_provider_both_keys_openai_wins(self) -> None:
        """OpenAI wins when multiple keys are present (tie-breaker)."""
        with patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "sk-test", "ANTHROPIC_API_KEY": "sk-ant-test"},
            clear=True,
        ):
            assert detect_provider() == "openai"

    def test_detect_provider_no_keys(self) -> None:
        """Returns None when no API keys are set."""
        with patch.dict(os.environ, {}, clear=True):
            assert detect_provider() is None


class TestGetProfileModels:
    """Test profile model retrieval."""

    def test_get_profile_models_openai(self) -> None:
        """Returns OpenAI models for 'openai' provider."""
        models = get_profile_models("openai")
        assert models["attacker"] == "gpt-4o-mini"
        assert models["judge"] == "gpt-4o"

    def test_get_profile_models_anthropic(self) -> None:
        """Returns Anthropic models for 'anthropic' provider."""
        models = get_profile_models("anthropic")
        assert "claude" in models["attacker"].lower()
        assert "claude" in models["judge"].lower()

    def test_get_profile_models_google(self) -> None:
        """Returns Google models for 'google' provider."""
        models = get_profile_models("google")
        assert "gemini" in models["attacker"].lower()
        assert "gemini" in models["judge"].lower()

    def test_get_profile_models_unknown_provider(self) -> None:
        """Raises ValueError for unknown provider."""
        with pytest.raises(ValueError, match="Unknown provider"):
            get_profile_models("unknown")


class TestInferProviderFromModel:
    """Test provider inference from model IDs."""

    @pytest.mark.parametrize(
        "model,expected",
        [
            ("gpt-4o", "openai"),
            ("gpt-4o-mini", "openai"),
            ("o1-preview", "openai"),
            ("claude-3-opus-20240229", "anthropic"),
            ("claude-haiku-4-20250514", "anthropic"),
            ("gemini-1.5-pro", "google"),
            ("gemini-2.0-flash", "google"),
            ("unknown-model", None),
            ("custom-local-model", None),
        ],
    )
    def test_infer_provider_from_model(self, model: str, expected: str | None) -> None:
        """Correctly infers provider from model ID."""
        assert infer_provider_from_model(model) == expected


class TestResolveConfigWithProvider:
    """Test config resolution with provider profiles."""

    def test_cli_provider_overrides_toml(self) -> None:
        """CLI --provider overrides toml provider."""
        cli = CLIOverrides(target_path="agent.py:fn", provider="anthropic")
        toml = TomlConfig(provider="openai")

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            config = resolve_config(cli, toml)

        assert config.provider == "anthropic"
        # Models should come from anthropic profile
        assert "claude" in config.attacker_model.lower()

    def test_toml_provider_used_when_no_cli(self) -> None:
        """TOML provider is used when CLI provider not set."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig(provider="google")

        with patch.dict(os.environ, {}, clear=True):
            config = resolve_config(cli, toml)

        assert config.provider == "google"
        assert "gemini" in config.attacker_model.lower()

    def test_auto_detect_provider_from_env(self) -> None:
        """Auto-detects provider when none specified."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig()

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=True):
            config = resolve_config(cli, toml)

        assert config.provider == "anthropic"
        assert config.provider_auto_detected is True

    def test_cli_model_overrides_profile(self) -> None:
        """CLI model override takes precedence over profile."""
        cli = CLIOverrides(
            target_path="agent.py:fn",
            provider="anthropic",
            judge_model="gpt-4o",  # Override with OpenAI model
        )
        toml = TomlConfig()

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=True):
            config = resolve_config(cli, toml)

        # Other models from Anthropic profile
        assert "claude" in config.attacker_model.lower()
        # But judge is overridden
        assert config.judge_model == "gpt-4o"

    def test_toml_model_overrides_profile(self) -> None:
        """TOML model override takes precedence over profile."""
        cli = CLIOverrides(target_path="agent.py:fn", provider="anthropic")
        toml = TomlConfig()
        toml.models.patcher = "gpt-4o"  # Override patcher

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=True):
            config = resolve_config(cli, toml)

        # Other models from Anthropic profile
        assert "claude" in config.attacker_model.lower()
        # But patcher is overridden
        assert config.patcher_model == "gpt-4o"

    def test_provider_auto_detected_flag_false_when_explicit(self) -> None:
        """provider_auto_detected is False when provider explicitly set."""
        cli = CLIOverrides(target_path="agent.py:fn", provider="openai")
        toml = TomlConfig()

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            config = resolve_config(cli, toml)

        assert config.provider == "openai"
        assert config.provider_auto_detected is False

    def test_provider_none_when_no_keys(self) -> None:
        """Provider is None when no keys and no explicit provider."""
        cli = CLIOverrides(target_path="agent.py:fn")
        toml = TomlConfig()

        with patch.dict(os.environ, {}, clear=True):
            config = resolve_config(cli, toml)

        assert config.provider is None
        # Falls back to defaults
        assert config.attacker_model == "gpt-4o-mini"


class TestCLIOverridesProvider:
    """Test CLIOverrides has provider field."""

    def test_cli_overrides_accepts_provider(self) -> None:
        """CLIOverrides model accepts provider field."""
        cli = CLIOverrides(target_path="agent.py:fn", provider="anthropic")
        assert cli.provider == "anthropic"

    def test_cli_overrides_provider_default_none(self) -> None:
        """CLIOverrides provider defaults to None."""
        cli = CLIOverrides(target_path="agent.py:fn")
        assert cli.provider is None
