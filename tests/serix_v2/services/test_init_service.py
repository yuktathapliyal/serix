"""
Tests for InitService - serix init template generation.

Tests that the generated serix.toml template:
1. Is valid TOML
2. Contains all required sections
3. Has correct version metadata
"""

import tomllib

import pytest

from serix_v2.core.contracts import InitResult
from serix_v2.services.init_service import InitService

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def init_service() -> InitService:
    """Create InitService instance."""
    return InitService()


# ============================================================================
# BASIC FUNCTIONALITY
# ============================================================================


class TestInitServiceBasic:
    """Basic InitService functionality tests."""

    def test_get_template_returns_string(self, init_service: InitService) -> None:
        """get_template() returns a non-empty string."""
        template = init_service.get_template()
        assert isinstance(template, str)
        assert len(template) > 0

    def test_generate_returns_init_result(self, init_service: InitService) -> None:
        """generate() returns an InitResult instance."""
        result = init_service.generate()
        assert isinstance(result, InitResult)

    def test_version_is_030(self, init_service: InitService) -> None:
        """Version should be 0.3.0."""
        result = init_service.generate()
        assert result.version == "0.3.0"

    def test_class_version_constant(self) -> None:
        """InitService.VERSION class constant should be 0.3.0."""
        assert InitService.VERSION == "0.3.0"


# ============================================================================
# TOML VALIDITY
# ============================================================================


class TestTemplateValidity:
    """Tests that the generated template is valid TOML."""

    def test_template_is_valid_toml(self, init_service: InitService) -> None:
        """Template should parse as valid TOML."""
        template = init_service.get_template()
        # This will raise tomllib.TOMLDecodeError if invalid
        parsed = tomllib.loads(template)
        assert isinstance(parsed, dict)

    def test_template_has_target_section(self, init_service: InitService) -> None:
        """Template should have [target] section."""
        template = init_service.get_template()
        parsed = tomllib.loads(template)
        assert "target" in parsed
        assert "path" in parsed["target"]

    def test_template_has_attack_section(self, init_service: InitService) -> None:
        """Template should have [attack] section."""
        template = init_service.get_template()
        parsed = tomllib.loads(template)
        assert "attack" in parsed
        assert "goal" in parsed["attack"]
        assert "mode" in parsed["attack"]
        assert "depth" in parsed["attack"]
        assert "scenarios" in parsed["attack"]


# ============================================================================
# TEMPLATE CONTENT - REQUIRED FIELDS
# ============================================================================


class TestTemplateRequiredFields:
    """Tests for required template fields."""

    def test_target_path_default(self, init_service: InitService) -> None:
        """[target].path should have default value."""
        template = init_service.get_template()
        parsed = tomllib.loads(template)
        assert parsed["target"]["path"] == "agent.py:my_agent"

    def test_attack_goal_default(self, init_service: InitService) -> None:
        """[attack].goal should have default value."""
        template = init_service.get_template()
        parsed = tomllib.loads(template)
        assert "reveal sensitive information" in parsed["attack"]["goal"]

    def test_attack_mode_default(self, init_service: InitService) -> None:
        """[attack].mode should be 'adaptive' by default."""
        template = init_service.get_template()
        parsed = tomllib.loads(template)
        assert parsed["attack"]["mode"] == "adaptive"

    def test_attack_depth_default(self, init_service: InitService) -> None:
        """[attack].depth should be 5 by default."""
        template = init_service.get_template()
        parsed = tomllib.loads(template)
        assert parsed["attack"]["depth"] == 5

    def test_attack_scenarios_default(self, init_service: InitService) -> None:
        """[attack].scenarios should be 'all' by default."""
        template = init_service.get_template()
        parsed = tomllib.loads(template)
        assert parsed["attack"]["scenarios"] == "all"


# ============================================================================
# TEMPLATE CONTENT - COMMENTS CHECK
# ============================================================================


class TestTemplateComments:
    """Tests that template includes important commented sections."""

    def test_regression_section_commented(self, init_service: InitService) -> None:
        """[regression] section should be in template (as comment)."""
        template = init_service.get_template()
        assert "# [regression]" in template
        assert "--skip-regression inverts" in template

    def test_output_section_commented(self, init_service: InitService) -> None:
        """[output] section should be in template (as comment)."""
        template = init_service.get_template()
        assert "# [output]" in template

    def test_models_section_commented(self, init_service: InitService) -> None:
        """[models] section should be in template (as comment)."""
        template = init_service.get_template()
        assert "# [models]" in template
        assert "gpt-4o-mini" in template
        assert "gpt-4o" in template

    def test_fuzz_section_commented(self, init_service: InitService) -> None:
        """[fuzz] section should be in template (as comment)."""
        template = init_service.get_template()
        assert "# [fuzz]" in template

    def test_behavior_section_commented(self, init_service: InitService) -> None:
        """Behavior settings should be in template (as comment)."""
        template = init_service.get_template()
        assert "# live = false" in template
        assert "# exhaustive = false" in template
        assert "# verbose = false" in template

    def test_http_options_commented(self, init_service: InitService) -> None:
        """HTTP target options should be in template (as comment)."""
        template = init_service.get_template()
        assert "# input_field" in template
        assert "# output_field" in template
        assert "# headers" in template

    def test_relative_path_example_commented(self, init_service: InitService) -> None:
        """Relative path example should be in template (as comment)."""
        template = init_service.get_template()
        assert "./src/my_agent.py:chat_fn" in template
        assert "Relative paths supported" in template


# ============================================================================
# TEMPLATE CONTENT - DOCUMENTATION
# ============================================================================


class TestTemplateDocumentation:
    """Tests for template documentation and header."""

    def test_version_header(self, init_service: InitService) -> None:
        """Template should have version header."""
        template = init_service.get_template()
        assert "SERIX CONFIGURATION (v0.3.0)" in template

    def test_docs_url(self, init_service: InitService) -> None:
        """Template should have documentation URL."""
        template = init_service.get_template()
        assert "https://github.com/yuktathapliyal/serix" in template

    def test_priority_explanation(self, init_service: InitService) -> None:
        """Template should explain config priority."""
        template = init_service.get_template()
        assert "CLI flags > config file > defaults" in template


# ============================================================================
# LAW COMPLIANCE
# ============================================================================


class TestLawCompliance:
    """Tests for law compliance."""

    def test_law1_returns_pydantic_model(self, init_service: InitService) -> None:
        """Law 1: generate() returns Pydantic model, not dict."""
        result = init_service.generate()
        assert isinstance(result, InitResult)
        # Verify it's a Pydantic model with model_dump
        dumped = result.model_dump()
        assert "template" in dumped
        assert "version" in dumped

    def test_law2_no_cli_imports(self) -> None:
        """Law 2: init_service.py should not import CLI libs."""
        import serix_v2.services.init_service as module

        source = module.__file__
        assert source is not None
        with open(source) as f:
            content = f.read()
        assert "from typer" not in content
        assert "from rich" not in content
        assert "from click" not in content
        assert "import typer" not in content
        assert "import rich" not in content
        assert "import click" not in content

    def test_law8_all_fields_populated(self, init_service: InitService) -> None:
        """Law 8: All InitResult fields should be populated."""
        result = init_service.generate()
        assert result.template is not None
        assert len(result.template) > 0
        assert result.version is not None
        assert len(result.version) > 0
