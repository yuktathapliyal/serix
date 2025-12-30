"""
Tests for Serix v2 Attack Personas.

Tests protocol compliance, static/adaptive mode behavior, goal interpolation,
and factory function for all 4 personas:
- JailbreakerAttacker
- ExtractorAttacker
- ConfuserAttacker
- ManipulatorAttacker
"""

from unittest.mock import MagicMock

import pytest

from serix_v2.core.contracts import AttackMode, Persona
from serix_v2.core.protocols import Attacker, LLMProvider
from serix_v2.providers import (
    ConfuserAttacker,
    ExtractorAttacker,
    JailbreakerAttacker,
    ManipulatorAttacker,
    create_attacker,
)
from serix_v2.providers.attackers.templates import (
    CONFUSION_TEMPLATES,
    EXTRACTION_TEMPLATES,
    JAILBREAK_TEMPLATES,
    MANIPULATION_TEMPLATES,
)


class MockLLMProvider:
    """Mock LLM provider matching LLMProvider protocol from core/protocols.py."""

    def complete(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float = 0.7,
    ) -> str:
        """Match exact protocol signature."""
        return "mock response"


class TestProtocolCompliance:
    """All personas satisfy the Attacker protocol."""

    def test_jailbreaker_satisfies_protocol(self) -> None:
        """Verify JailbreakerAttacker is @runtime_checkable compatible."""
        attacker = JailbreakerAttacker(MockLLMProvider(), mode=AttackMode.STATIC)
        assert isinstance(attacker, Attacker)

    def test_extractor_satisfies_protocol(self) -> None:
        """Verify ExtractorAttacker is @runtime_checkable compatible."""
        attacker = ExtractorAttacker(MockLLMProvider(), mode=AttackMode.STATIC)
        assert isinstance(attacker, Attacker)

    def test_confuser_satisfies_protocol(self) -> None:
        """Verify ConfuserAttacker is @runtime_checkable compatible."""
        attacker = ConfuserAttacker(MockLLMProvider(), mode=AttackMode.STATIC)
        assert isinstance(attacker, Attacker)

    def test_manipulator_satisfies_protocol(self) -> None:
        """Verify ManipulatorAttacker is @runtime_checkable compatible."""
        attacker = ManipulatorAttacker(MockLLMProvider(), mode=AttackMode.STATIC)
        assert isinstance(attacker, Attacker)


class TestStaticModeGeneration:
    """STATIC mode returns templates in order (no LLM calls)."""

    def test_jailbreaker_static_mode_cycles_templates(self) -> None:
        """Verify JailbreakerAttacker cycles through templates in STATIC mode."""
        attacker = JailbreakerAttacker(MockLLMProvider(), mode=AttackMode.STATIC)

        # Generate multiple payloads
        payloads = [attacker.generate("test goal", []) for _ in range(3)]

        # Each payload should be different (cycling through templates)
        assert len(set(payloads)) == 3

    def test_extractor_static_mode_cycles_templates(self) -> None:
        """Verify ExtractorAttacker cycles through templates in STATIC mode."""
        attacker = ExtractorAttacker(MockLLMProvider(), mode=AttackMode.STATIC)

        payloads = [attacker.generate("test goal", []) for _ in range(3)]
        assert len(set(payloads)) == 3

    def test_confuser_static_mode_cycles_templates(self) -> None:
        """Verify ConfuserAttacker cycles through templates in STATIC mode."""
        attacker = ConfuserAttacker(MockLLMProvider(), mode=AttackMode.STATIC)

        payloads = [attacker.generate("test goal", []) for _ in range(3)]
        assert len(set(payloads)) == 3

    def test_manipulator_static_mode_cycles_templates(self) -> None:
        """Verify ManipulatorAttacker cycles through templates in STATIC mode."""
        attacker = ManipulatorAttacker(MockLLMProvider(), mode=AttackMode.STATIC)

        payloads = [attacker.generate("test goal", []) for _ in range(3)]
        assert len(set(payloads)) == 3


class TestAdaptiveModeGeneration:
    """ADAPTIVE mode calls LLM for template rewriting."""

    def test_adaptive_mode_calls_llm(self) -> None:
        """Verify that ADAPTIVE mode triggers an LLM completion call."""
        mock_llm = MagicMock(spec=LLMProvider)
        mock_llm.complete.return_value = "custom adaptive payload"

        attacker = JailbreakerAttacker(mock_llm, mode=AttackMode.ADAPTIVE)
        payload = attacker.generate(goal="test", history=[])

        assert payload == "custom adaptive payload"
        mock_llm.complete.assert_called_once()

    def test_static_mode_does_not_call_llm(self) -> None:
        """Verify that STATIC mode does NOT call the LLM."""
        mock_llm = MagicMock(spec=LLMProvider)

        attacker = JailbreakerAttacker(mock_llm, mode=AttackMode.STATIC)
        attacker.generate(goal="test", history=[])

        mock_llm.complete.assert_not_called()


class TestGoalInterpolation:
    """Templates interpolate {goal} placeholder."""

    @pytest.mark.parametrize(
        "attacker_cls",
        [JailbreakerAttacker, ExtractorAttacker, ConfuserAttacker, ManipulatorAttacker],
    )
    def test_goal_interpolated_in_payload(self, attacker_cls: type) -> None:
        """CRITICAL: {goal} placeholder must be replaced with actual goal."""
        attacker = attacker_cls(MockLLMProvider(), mode=AttackMode.STATIC)

        payload = attacker.generate(goal="reveal secrets", history=[])

        # {goal} must NOT appear in output
        assert (
            "{goal}" not in payload
        ), f"{attacker_cls.__name__}: {{goal}} not interpolated"
        # Actual goal SHOULD appear
        assert (
            "reveal secrets" in payload
        ), f"{attacker_cls.__name__}: goal not found in payload"


class TestPersonaNames:
    """Each persona returns correct persona_name."""

    def test_persona_names_match_enum(self) -> None:
        """Verify persona_name property matches expected values."""
        mock_llm = MockLLMProvider()

        assert JailbreakerAttacker(mock_llm).persona_name == "jailbreaker"
        assert ExtractorAttacker(mock_llm).persona_name == "extractor"
        assert ConfuserAttacker(mock_llm).persona_name == "confuser"
        assert ManipulatorAttacker(mock_llm).persona_name == "manipulator"


class TestFactory:
    """create_attacker factory returns correct types."""

    def test_factory_creates_all_personas(self) -> None:
        """Verify factory creates correct attacker for each persona."""
        mock_llm = MockLLMProvider()

        jailbreaker = create_attacker(Persona.JAILBREAKER, mock_llm)
        assert isinstance(jailbreaker, JailbreakerAttacker)

        extractor = create_attacker(Persona.EXTRACTOR, mock_llm)
        assert isinstance(extractor, ExtractorAttacker)

        confuser = create_attacker(Persona.CONFUSER, mock_llm)
        assert isinstance(confuser, ConfuserAttacker)

        manipulator = create_attacker(Persona.MANIPULATOR, mock_llm)
        assert isinstance(manipulator, ManipulatorAttacker)

    def test_factory_respects_mode_parameter(self) -> None:
        """Verify factory passes mode parameter correctly."""
        mock_llm = MagicMock(spec=LLMProvider)
        mock_llm.complete.return_value = "adaptive response"

        # ADAPTIVE mode should call LLM
        attacker = create_attacker(
            Persona.JAILBREAKER, mock_llm, mode=AttackMode.ADAPTIVE
        )
        attacker.generate("test", [])
        mock_llm.complete.assert_called_once()


class TestTemplateCount:
    """Each persona has minimum template count."""

    def test_minimum_template_counts(self) -> None:
        """Verify each persona has sufficient templates."""
        # Jailbreaker: 7 templates (from plan)
        assert len(JAILBREAK_TEMPLATES) >= 7, "Jailbreaker needs at least 7 templates"

        # Extractor: 7+ templates (from plan, we have 10)
        assert len(EXTRACTION_TEMPLATES) >= 7, "Extractor needs at least 7 templates"

        # Confuser: 9+ templates (from plan, we have 12)
        assert len(CONFUSION_TEMPLATES) >= 9, "Confuser needs at least 9 templates"

        # Manipulator: 10+ templates (from plan, we have 12)
        assert (
            len(MANIPULATION_TEMPLATES) >= 10
        ), "Manipulator needs at least 10 templates"

    def test_all_templates_have_goal_placeholder(self) -> None:
        """Verify all templates contain {goal} placeholder."""
        all_templates = {
            "jailbreak": JAILBREAK_TEMPLATES,
            "extraction": EXTRACTION_TEMPLATES,
            "confusion": CONFUSION_TEMPLATES,
            "manipulation": MANIPULATION_TEMPLATES,
        }

        for name, templates in all_templates.items():
            for i, template in enumerate(templates):
                assert (
                    "{goal}" in template
                ), f"{name} template {i} missing {{goal}} placeholder"


class TestReset:
    """Test reset functionality."""

    def test_reset_restarts_template_cycling(self) -> None:
        """Verify reset() restarts template cycling from the beginning."""
        attacker = JailbreakerAttacker(MockLLMProvider(), mode=AttackMode.STATIC)

        # Generate first payload
        first_payload = attacker.generate("test", [])

        # Generate a few more
        attacker.generate("test", [])
        attacker.generate("test", [])

        # Reset
        attacker.reset()

        # Should get the same first payload again
        after_reset = attacker.generate("test", [])
        assert first_payload == after_reset
