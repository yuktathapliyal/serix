"""
Tests for the Credential Preflight Service (Phase 19).

Tests Law 2 compliance and functional correctness of the credential
analysis and validation logic.
"""

import os
from unittest.mock import patch

from serix_v2.core.contracts import ProviderRequirement
from serix_v2.core.errors import TargetCredentialError
from serix_v2.services.credential_preflight import (
    analyze_requirements,
    collect_serix_providers,
    run_dry_preflight,
    update_requirement_presence,
)


class TestCollectSerixProviders:
    """Tests for collect_serix_providers function."""

    def test_base_provider_with_no_overrides(self) -> None:
        """When only base provider set, all roles use that provider."""
        result = collect_serix_providers("openai", {})
        assert result == {
            "openai": ["attacker", "critic", "analyzer", "judge", "patcher"]
        }

    def test_base_provider_with_matching_overrides(self) -> None:
        """When overrides match base provider, roles go to that provider."""
        result = collect_serix_providers(
            "openai",
            {"attacker": "gpt-4o-mini", "judge": "gpt-4o"},
        )
        assert "openai" in result
        assert "attacker" in result["openai"]
        assert "judge" in result["openai"]

    def test_mixed_provider_overrides(self) -> None:
        """When overrides use different providers, roles are split."""
        result = collect_serix_providers(
            "openai",
            {"attacker": "gpt-4o-mini", "judge": "claude-sonnet-4-20250514"},
        )
        assert "openai" in result
        assert "anthropic" in result
        assert "attacker" in result["openai"]
        assert "judge" in result["anthropic"]

    def test_no_base_provider_with_overrides(self) -> None:
        """When no base provider, infer from overrides."""
        result = collect_serix_providers(
            None,
            {"attacker": "gpt-4o-mini", "judge": "gpt-4o"},
        )
        assert "openai" in result
        assert "attacker" in result["openai"]
        assert "judge" in result["openai"]

    def test_google_provider_detection(self) -> None:
        """Google model prefixes are detected correctly."""
        result = collect_serix_providers(
            None,
            {"attacker": "gemini-2.0-flash", "judge": "gemini-2.5-pro"},
        )
        assert "google" in result
        assert "attacker" in result["google"]
        assert "judge" in result["google"]


class TestAnalyzeRequirements:
    """Tests for analyze_requirements function."""

    def test_single_provider_present(self) -> None:
        """When key is present, is_present is True."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-123"}):
            result = analyze_requirements(
                serix_provider="openai",
                model_overrides={},
                target_provider=None,
            )
        assert len(result.requirements) == 1
        assert result.requirements[0].provider == "openai"
        assert result.requirements[0].is_present is True
        assert result.all_present is True
        assert result.missing_count == 0

    def test_single_provider_missing(self) -> None:
        """When key is missing, is_present is False."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear the key if it exists
            os.environ.pop("OPENAI_API_KEY", None)
            result = analyze_requirements(
                serix_provider="openai",
                model_overrides={},
                target_provider=None,
            )
        assert result.requirements[0].is_present is False
        assert result.all_present is False
        assert result.missing_count == 1

    def test_multiple_providers_needed(self) -> None:
        """When both Serix and target need different providers."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-123"}, clear=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            result = analyze_requirements(
                serix_provider="openai",
                model_overrides={},
                target_provider="anthropic",
            )
        assert len(result.requirements) == 2

        # OpenAI should be present
        openai_req = next(r for r in result.requirements if r.provider == "openai")
        assert openai_req.is_present is True
        assert openai_req.is_target is False

        # Anthropic should be missing
        anthropic_req = next(
            r for r in result.requirements if r.provider == "anthropic"
        )
        assert anthropic_req.is_present is False
        assert anthropic_req.is_target is True

        assert result.missing_count == 1
        assert result.all_present is False

    def test_same_provider_for_serix_and_target(self) -> None:
        """When Serix and target use same provider, roles are merged."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-123"}):
            result = analyze_requirements(
                serix_provider="openai",
                model_overrides={},
                target_provider="openai",
            )
        # Should only be one requirement with merged roles
        assert len(result.requirements) == 1
        req = result.requirements[0]
        assert "target" in req.roles
        assert "attacker" in req.roles

    def test_target_provider_source_tracking(self) -> None:
        """target_provider_source is set correctly."""
        result = analyze_requirements(
            serix_provider="openai",
            model_overrides={},
            target_provider="anthropic",
        )
        assert result.target_provider == "anthropic"
        assert result.target_provider_source == "config"

    def test_no_target_provider_source_when_none(self) -> None:
        """target_provider_source is None when no target provider."""
        result = analyze_requirements(
            serix_provider="openai",
            model_overrides={},
            target_provider=None,
        )
        assert result.target_provider is None
        assert result.target_provider_source is None

    def test_missing_requirements_property(self) -> None:
        """missing_requirements returns only missing ones."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            result = analyze_requirements(
                serix_provider="openai",
                model_overrides={},
                target_provider="anthropic",
            )
        missing = result.missing_requirements
        assert len(missing) == 1
        assert missing[0].provider == "anthropic"

    def test_present_requirements_property(self) -> None:
        """present_requirements returns only present ones."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            result = analyze_requirements(
                serix_provider="openai",
                model_overrides={},
                target_provider="anthropic",
            )
        present = result.present_requirements
        assert len(present) == 1
        assert present[0].provider == "openai"


class TestRunDryPreflight:
    """Tests for run_dry_preflight function."""

    def test_target_succeeds_returns_none_none(self) -> None:
        """When target works, returns (None, None)."""

        def working_target(prompt: str) -> str:
            return "Hello!"

        detected, error = run_dry_preflight(working_target, "test-id", "test.py:fn")
        assert detected is None
        assert error is None

    def test_target_credential_error_detected(self) -> None:
        """When target throws TargetCredentialError, provider is detected."""

        def failing_target(prompt: str) -> str:
            raise TargetCredentialError(
                target_id="test-id",
                locator="test.py:fn",
                original_error="OpenAI API key is invalid",
            )

        detected, error = run_dry_preflight(failing_target, "test-id", "test.py:fn")
        assert detected == "openai"
        assert error == "OpenAI API key is invalid"

    def test_generic_openai_error_detected(self) -> None:
        """When target throws generic error with OpenAI mention."""

        def failing_target(prompt: str) -> str:
            raise Exception("OpenAI API error: invalid api key")

        detected, error = run_dry_preflight(failing_target, "test-id", "test.py:fn")
        assert detected == "openai"
        assert "OpenAI" in error

    def test_anthropic_error_detected(self) -> None:
        """When target throws error mentioning Anthropic."""

        def failing_target(prompt: str) -> str:
            raise Exception("Anthropic API error: authentication failed")

        detected, error = run_dry_preflight(failing_target, "test-id", "test.py:fn")
        assert detected == "anthropic"

    def test_google_error_detected(self) -> None:
        """When target throws error mentioning Google/Gemini."""

        def failing_target(prompt: str) -> str:
            raise Exception("Google Gemini API: invalid credentials")

        detected, error = run_dry_preflight(failing_target, "test-id", "test.py:fn")
        assert detected == "google"

    def test_auth_pattern_detected_without_provider(self) -> None:
        """When error has auth patterns but no provider hint."""

        def failing_target(prompt: str) -> str:
            raise Exception("401 Unauthorized")

        detected, error = run_dry_preflight(failing_target, "test-id", "test.py:fn")
        # Can't determine provider, but error is returned
        assert detected is None
        assert "401" in error

    def test_unrelated_error_returns_none_with_error(self) -> None:
        """When target throws unrelated error."""

        def failing_target(prompt: str) -> str:
            raise ValueError("Something else went wrong")

        detected, error = run_dry_preflight(failing_target, "test-id", "test.py:fn")
        assert detected is None
        assert error is None or "wrong" in error.lower()


class TestUpdateRequirementPresence:
    """Tests for update_requirement_presence function."""

    def test_updates_presence_from_env(self) -> None:
        """Presence is updated based on current environment."""
        reqs = [
            ProviderRequirement(
                provider="openai",
                env_var="OPENAI_API_KEY",
                roles=["attacker"],
                is_present=False,
            ),
        ]

        # Initially not present
        assert reqs[0].is_present is False

        # Add to env
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-new-key"}):
            updated = update_requirement_presence(reqs)
            assert updated[0].is_present is True


class TestLaw2Compliance:
    """Verify Law 2: CLI-is-a-Guest compliance."""

    def test_no_cli_imports_in_service(self) -> None:
        """Verify no typer/rich imports in credential_preflight.py."""
        import serix_v2.services.credential_preflight as module

        source = module.__file__
        assert source is not None

        with open(source) as f:
            content = f.read()

        # Should not have any CLI framework imports
        assert "from typer" not in content
        assert "import typer" not in content
        assert "from rich" not in content
        assert "import rich" not in content
        assert "from click" not in content
        assert "import click" not in content
