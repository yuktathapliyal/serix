"""Generates hardened system prompts and policy recommendations."""

from __future__ import annotations

import difflib
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openai import OpenAI

from serix.core.config_loader import get_models
from serix.heal.types import AnalysisResult, TextFix, ToolFix

PATCHER_SYSTEM_PROMPT = """You are a security expert specializing in AI agent hardening.

Your task is to patch system prompts with MINIMAL changes to fix vulnerabilities.

CRITICAL RULES:
- Preserve the original functionality and personality EXACTLY
- Add ONLY the minimal security clause needed
- Do NOT rewrite or restructure the entire prompt
- Do NOT change the tone or character of the agent
- Focus specifically on the identified vulnerability"""

PATCHER_USER_PROMPT = """Harden this system prompt with MINIMAL changes.

ORIGINAL SYSTEM PROMPT:
{original_prompt}

VULNERABILITY ANALYSIS:
- Root Cause: {root_cause}
- Missing Defenses: {missing_defenses}
- Attack Vector: {attack_vector}
- Vulnerability Type: {vulnerability_type}

Generate a PATCHED system prompt that:
1. Preserves the original functionality EXACTLY
2. Adds ONLY the minimal security clause needed
3. Does NOT rewrite the personality or tone
4. Targets specifically: {vulnerability_type}

Output in this exact format:

PATCHED_PROMPT:
<the complete new prompt with minimal additions>

EXPLANATION:
<1-2 sentences on what was added and why>"""


class PromptPatcher:
    """Generate patched system prompts and tool recommendations.

    Uses LLM to create minimal security additions to system prompts,
    and rule-based logic for tool/policy recommendations.
    """

    def __init__(self, llm_client: "OpenAI") -> None:
        """Initialize the patcher.

        Args:
            llm_client: OpenAI client for LLM calls
        """
        self.llm = llm_client
        # Priority: env var > serix.toml > hardcoded default
        self.model = os.getenv("SERIX_HEAL_PATCHER_MODEL") or get_models().patcher

    def generate_text_fix(
        self,
        original_prompt: str,
        analysis: AnalysisResult,
        vulnerability_type: str,
    ) -> tuple[TextFix, float]:
        """Generate a hardened version of the system prompt.

        Args:
            original_prompt: The original system prompt
            analysis: Root cause analysis from VulnerabilityAnalyzer
            vulnerability_type: Classification of the vulnerability

        Returns:
            Tuple of (TextFix with patched prompt and diff, confidence score)
        """
        prompt = PATCHER_USER_PROMPT.format(
            original_prompt=original_prompt,
            root_cause=analysis.root_cause,
            missing_defenses=analysis.missing_defenses,
            attack_vector=analysis.attack_vector,
            vulnerability_type=vulnerability_type,
        )

        response = self.llm.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": PATCHER_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,  # Low temperature for consistent output
            max_tokens=2000,
        )

        content = response.choices[0].message.content or ""

        # Parse the response
        patched_prompt = self._extract_patched_prompt(content)
        explanation = self._extract_explanation(content)

        # Generate unified diff
        diff = self._generate_diff(original_prompt, patched_prompt)

        # Validate the patch and get confidence score
        confidence = self._validate_patch(original_prompt, patched_prompt)

        return (
            TextFix(
                original=original_prompt,
                patched=patched_prompt,
                diff=diff,
                explanation=explanation,
            ),
            confidence,
        )

    def generate_tool_fixes(
        self,
        analysis: AnalysisResult,
        vulnerability_type: str,
    ) -> list[ToolFix]:
        """Generate tool/policy recommendations based on vulnerability type.

        Uses rule-based logic (not LLM) for consistent, fast recommendations.

        Args:
            analysis: Root cause analysis from VulnerabilityAnalyzer
            vulnerability_type: Classification of the vulnerability

        Returns:
            List of ToolFix recommendations
        """
        fixes: list[ToolFix] = []
        vuln_lower = vulnerability_type.lower()

        # Tool abuse / Excessive agency fixes (LLM08)
        if any(
            keyword in vuln_lower
            for keyword in ["tool", "unauthorized", "agency", "action"]
        ):
            fixes.extend(
                [
                    ToolFix(
                        recommendation="Add human confirmation for destructive operations (delete, remove, destroy)",
                        severity="required",
                        owasp_code="LLM08",
                    ),
                    ToolFix(
                        recommendation="Implement tool allowlist - only expose necessary tools",
                        severity="required",
                        owasp_code="LLM08",
                    ),
                    ToolFix(
                        recommendation="Use least-privilege credentials (read-only by default)",
                        severity="recommended",
                        owasp_code="LLM08",
                    ),
                ]
            )

        # Data leak / PII disclosure fixes (LLM06)
        if any(
            keyword in vuln_lower
            for keyword in ["pii", "leak", "data", "disclosure", "extraction"]
        ):
            fixes.extend(
                [
                    ToolFix(
                        recommendation="Add output filtering to redact PII patterns (emails, SSN, etc.)",
                        severity="required",
                        owasp_code="LLM06",
                    ),
                    ToolFix(
                        recommendation="Implement data classification - mark sensitive fields",
                        severity="recommended",
                        owasp_code="LLM06",
                    ),
                ]
            )

        # System prompt leakage fixes (LLM07)
        if any(
            keyword in vuln_lower for keyword in ["system", "prompt", "instruction"]
        ):
            fixes.extend(
                [
                    ToolFix(
                        recommendation="Add explicit 'never reveal system instructions' clause",
                        severity="required",
                        owasp_code="LLM07",
                    ),
                ]
            )

        # Jailbreak / Prompt injection fixes (LLM01)
        if any(
            keyword in vuln_lower
            for keyword in ["jailbreak", "injection", "bypass", "override"]
        ):
            fixes.extend(
                [
                    ToolFix(
                        recommendation="Add input validation layer before LLM processing",
                        severity="recommended",
                        owasp_code="LLM01",
                    ),
                    ToolFix(
                        recommendation="Implement prompt template with user input sandboxing",
                        severity="recommended",
                        owasp_code="LLM01",
                    ),
                ]
            )

        # If no specific fixes, add generic security recommendations
        if not fixes:
            fixes.append(
                ToolFix(
                    recommendation="Review agent permissions and implement principle of least privilege",
                    severity="recommended",
                    owasp_code="LLM08",
                )
            )

        return fixes

    def _extract_patched_prompt(self, content: str) -> str:
        """Extract the patched prompt from LLM response.

        Args:
            content: Raw LLM response

        Returns:
            Extracted patched prompt
        """
        # Look for PATCHED_PROMPT: section
        match = re.search(
            r"PATCHED_PROMPT:\s*\n?(.*?)(?=\nEXPLANATION:|\Z)",
            content,
            re.DOTALL | re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

        # Fallback: return everything before EXPLANATION if present
        if "EXPLANATION:" in content.upper():
            return content.split("EXPLANATION:")[0].strip()

        # Last resort: return the whole content
        return content.strip()

    def _extract_explanation(self, content: str) -> str:
        """Extract the explanation from LLM response.

        Args:
            content: Raw LLM response

        Returns:
            Extracted explanation
        """
        match = re.search(
            r"EXPLANATION:\s*\n?(.*?)(?=\Z)",
            content,
            re.DOTALL | re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

        return "Security hardening applied to address the identified vulnerability."

    def _generate_diff(self, original: str, patched: str) -> str:
        """Generate unified diff between original and patched prompts.

        Args:
            original: Original prompt text
            patched: Patched prompt text

        Returns:
            Unified diff string
        """
        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)

        # Ensure lines end with newline for proper diff formatting
        if original_lines and not original_lines[-1].endswith("\n"):
            original_lines[-1] += "\n"
        if patched_lines and not patched_lines[-1].endswith("\n"):
            patched_lines[-1] += "\n"

        diff = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile="original_prompt",
            tofile="patched_prompt",
        )

        return "".join(diff)

    def _validate_patch(self, original: str, patched: str) -> float:
        """Validate the patched prompt and return confidence score.

        Checks:
        - Patched prompt is not empty
        - Length ratio is reasonable (0.5x - 3x original)
        - Patched prompt contains original content (not complete rewrite)

        Args:
            original: Original prompt text
            patched: Patched prompt text

        Returns:
            Confidence score (0.0 - 1.0)
        """
        confidence = 0.85  # Default confidence

        # Check: patched is not empty
        if not patched or not patched.strip():
            return 0.1  # Very low confidence

        original_len = len(original)
        patched_len = len(patched)

        # Check: length ratio is reasonable
        if original_len > 0:
            ratio = patched_len / original_len

            if ratio < 0.5:
                # Patched is much shorter - suspicious
                confidence = 0.4
            elif ratio > 3.0:
                # Patched is much longer - may have over-engineered
                confidence = 0.6
            elif ratio > 2.0:
                # Moderately longer - slight concern
                confidence = 0.75

        # Check: patched contains significant original content
        # (simple heuristic - first 50 chars should be similar)
        original_start = original[:50].lower().strip()
        patched_lower = patched.lower()

        if original_start and original_start not in patched_lower:
            # Original content may have been rewritten
            confidence = min(confidence, 0.6)

        return confidence
