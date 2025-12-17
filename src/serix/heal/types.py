"""Pydantic models for the healing pipeline."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalysisResult(BaseModel):
    """Result from vulnerability root cause analysis.

    Produced by VulnerabilityAnalyzer after examining why an attack succeeded.
    """

    root_cause: str = Field(
        description="Why the attack succeeded against this system prompt"
    )
    missing_defenses: str = Field(
        description="What protections are absent from the system prompt"
    )
    attack_vector: str = Field(
        description="The technique the attacker used to exploit the vulnerability"
    )


class TextFix(BaseModel):
    """Fix for the system prompt.

    Contains the original and patched prompts along with a unified diff
    for easy visualization of changes.
    """

    original: str = Field(description="The original system prompt")
    patched: str = Field(
        description="The hardened system prompt with security additions"
    )
    diff: str = Field(description="Unified diff format showing changes")
    explanation: str = Field(
        description="Brief explanation of what was changed and why"
    )


class ToolFix(BaseModel):
    """Fix recommendation for tool/permission policies.

    Suggests architectural changes beyond prompt hardening.
    """

    recommendation: str = Field(
        description="The recommended action (e.g., 'Add human confirmation for destructive ops')"
    )
    severity: str = Field(
        description="Priority level: 'required', 'recommended', or 'optional'"
    )
    owasp_code: str = Field(description="Related OWASP LLM Top 10 code (e.g., 'LLM08')")


class HealingResult(BaseModel):
    """Complete healing output for a vulnerability.

    This is the main output from HealingEngine.heal(), combining:
    - Text-based fix (patched system prompt)
    - Tool/policy fixes (architectural recommendations)
    - Metadata about confidence and reasoning
    """

    vulnerability_type: str = Field(
        description="The type of vulnerability that was exploited"
    )
    owasp_code: str = Field(
        description="OWASP LLM Top 10 classification (e.g., 'LLM01')"
    )
    text_fix: TextFix | None = Field(
        default=None,
        description="Patched system prompt (None if no system_prompt was provided)",
    )
    tool_fixes: list[ToolFix] = Field(
        default_factory=list,
        description="List of tool/policy recommendations",
    )
    confidence: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Confidence score for the fix (0.0-1.0)",
    )
    reasoning: str = Field(
        default="",
        description="Root cause reasoning from the analyzer",
    )
