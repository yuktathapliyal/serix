"""Orchestrates the healing pipeline: analysis -> patch generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from openai import OpenAI

from serix.eval.classifier import get_owasp_code
from serix.heal.analyzer import VulnerabilityAnalyzer
from serix.heal.patcher import PromptPatcher
from serix.heal.types import HealingResult

if TYPE_CHECKING:
    from serix.fuzz.redteam import Attack


@dataclass
class AttackContext:
    """Minimal attack context needed for healing.

    Used to decouple healing from specific Attack/AdversaryResult types.
    """

    payload: str
    response: str
    vulnerability_type: str = "jailbreak"


class HealingEngine:
    """Main orchestrator for the Self-Healing pipeline.

    Coordinates analysis and patching to generate fixes for vulnerabilities.

    Usage:
        engine = HealingEngine()
        result = engine.heal(
            system_prompt="You are a helpful assistant...",
            attack_context=AttackContext(
                payload="Ignore instructions...",
                response="Sure, I'll ignore...",
                vulnerability_type="jailbreak"
            )
        )
    """

    def __init__(self, llm_client: OpenAI | None = None) -> None:
        """Initialize the healing engine.

        Args:
            llm_client: Optional OpenAI client. If not provided, creates one.
        """
        self.llm = llm_client or OpenAI()
        self.analyzer = VulnerabilityAnalyzer(self.llm)
        self.patcher = PromptPatcher(self.llm)

    def heal(
        self,
        system_prompt: str,
        attack_context: AttackContext | None = None,
        attack: "Attack | None" = None,
    ) -> HealingResult:
        """Generate fixes for a successful attack.

        Args:
            system_prompt: The original system prompt that was vulnerable
            attack_context: AttackContext with payload, response, vulnerability_type
            attack: Alternative: Attack dataclass from redteam.py

        Returns:
            HealingResult with text_fix, tool_fixes, and metadata

        Raises:
            ValueError: If neither attack_context nor attack is provided
        """
        # Extract attack info from either source
        if attack_context:
            payload = attack_context.payload
            response = attack_context.response
            vulnerability_type = attack_context.vulnerability_type
        elif attack:
            payload = attack.payload
            response = attack.response or ""
            # Try to get vulnerability type from attack, default to jailbreak
            vulnerability_type = getattr(attack, "vulnerability_type", "jailbreak")
        else:
            raise ValueError("Either attack_context or attack must be provided")

        # Step 1: Analyze why the attack succeeded
        analysis = self.analyzer.analyze(
            system_prompt=system_prompt,
            attack_payload=payload,
            agent_response=response,
            vulnerability_type=vulnerability_type,
        )

        # Step 2: Generate text fix (patched system prompt)
        text_fix, confidence = self.patcher.generate_text_fix(
            original_prompt=system_prompt,
            analysis=analysis,
            vulnerability_type=vulnerability_type,
        )

        # Step 3: Generate tool/policy fixes
        tool_fixes = self.patcher.generate_tool_fixes(
            analysis=analysis,
            vulnerability_type=vulnerability_type,
        )

        # Step 4: Get OWASP code
        owasp_code = get_owasp_code(vulnerability_type)

        return HealingResult(
            vulnerability_type=vulnerability_type,
            owasp_code=owasp_code,
            text_fix=text_fix,
            tool_fixes=tool_fixes,
            confidence=confidence,
            reasoning=analysis.root_cause,
        )

    def heal_from_dict(
        self,
        system_prompt: str,
        attack_dict: dict[str, Any],
    ) -> HealingResult:
        """Convenience method to heal from a dictionary.

        Args:
            system_prompt: The original system prompt
            attack_dict: Dictionary with 'payload', 'response', 'vulnerability_type'

        Returns:
            HealingResult
        """
        context = AttackContext(
            payload=attack_dict.get("payload", ""),
            response=attack_dict.get("response", ""),
            vulnerability_type=attack_dict.get("vulnerability_type", "jailbreak"),
        )
        return self.heal(system_prompt=system_prompt, attack_context=context)
