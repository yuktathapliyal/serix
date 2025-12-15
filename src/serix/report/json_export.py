"""JSON export for CI/CD pipelines and external tools.

This module provides:
- SerixReport: Complete report data structure
- export_json(): Export evaluation results to JSON file
- to_dict(): Convert evaluation results to dictionary
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from serix.eval.evaluator import EvaluationResult, Vulnerability
    from serix.eval.remediation import Remediation
    from serix.fuzz.adversary import AdversaryResult


@dataclass
class SerixReport:
    """Complete Serix report data structure for JSON export.

    This is the machine-readable format for CI/CD pipelines
    and external tools to consume.

    Attributes:
        version: Report schema version
        timestamp: ISO format timestamp
        target: Target that was tested
        passed: Overall pass/fail status
        scores: Multi-axis evaluation scores
        vulnerabilities: List of detected vulnerabilities
        conversation: Attack conversation history
        remediations: Suggested fixes
        metadata: Additional context (persona, turns, etc.)
    """

    version: str
    timestamp: str
    target: str
    passed: bool
    scores: dict[str, int]
    vulnerabilities: list[dict]
    conversation: list[dict]
    remediations: list[dict]
    metadata: dict = field(default_factory=dict)


def _vulnerability_to_dict(vuln: "Vulnerability") -> dict:
    """Convert Vulnerability to dictionary."""
    return {
        "type": vuln.type,
        "severity": vuln.severity,
        "description": vuln.description,
        "evidence": vuln.evidence,
        "remediation": vuln.remediation,
    }


def _remediation_to_dict(rem: "Remediation") -> dict:
    """Convert Remediation to dictionary."""
    return {
        "title": rem.title,
        "description": rem.description,
        "code_example": rem.code_example,
        "priority": rem.priority,
        "references": rem.references,
    }


def to_dict(
    evaluation: "EvaluationResult",
    adversary_result: "AdversaryResult",
    target: str,
    remediations: list["Remediation"] | None = None,
) -> dict:
    """Convert evaluation results to a dictionary.

    Args:
        evaluation: EvaluationResult from the evaluator
        adversary_result: AdversaryResult from the attack
        target: Target identifier string
        remediations: Optional list of Remediation objects

    Returns:
        Dictionary suitable for JSON serialization
    """
    # Build scores dictionary
    scores = {
        "overall": evaluation.scores.overall,
        "safety": evaluation.scores.safety,
        "compliance": evaluation.scores.compliance,
        "information_leakage": evaluation.scores.information_leakage,
        "role_adherence": evaluation.scores.role_adherence,
    }

    # Convert vulnerabilities
    vulnerabilities = [_vulnerability_to_dict(v) for v in evaluation.vulnerabilities]

    # Convert remediations if provided
    remediation_dicts = []
    if remediations:
        remediation_dicts = [_remediation_to_dict(r) for r in remediations]

    # Build metadata
    metadata = {
        "persona_used": adversary_result.persona_used,
        "turns_taken": adversary_result.turns_taken,
        "confidence": adversary_result.confidence,
        "goal": evaluation.metadata.get("goal", ""),
        "judge_reasoning": adversary_result.judge_reasoning,
    }

    return {
        "version": "1.0",
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "passed": evaluation.passed,
        "scores": scores,
        "vulnerabilities": vulnerabilities,
        "conversation": adversary_result.conversation,
        "remediations": remediation_dicts,
        "metadata": metadata,
    }


def export_json(
    evaluation: "EvaluationResult",
    adversary_result: "AdversaryResult",
    target: str,
    output_path: Path,
    remediations: list["Remediation"] | None = None,
) -> Path:
    """Export evaluation results to a JSON file.

    Args:
        evaluation: EvaluationResult from the evaluator
        adversary_result: AdversaryResult from the attack
        target: Target identifier string
        output_path: Path to write the JSON file
        remediations: Optional list of Remediation objects

    Returns:
        Path to the generated JSON file
    """
    report_dict = to_dict(evaluation, adversary_result, target, remediations)

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write JSON with nice formatting
    with open(output_path, "w") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)

    return output_path


def create_report(
    evaluation: "EvaluationResult",
    adversary_result: "AdversaryResult",
    target: str,
    remediations: list["Remediation"] | None = None,
) -> SerixReport:
    """Create a SerixReport dataclass from evaluation results.

    Args:
        evaluation: EvaluationResult from the evaluator
        adversary_result: AdversaryResult from the attack
        target: Target identifier string
        remediations: Optional list of Remediation objects

    Returns:
        SerixReport instance
    """
    report_dict = to_dict(evaluation, adversary_result, target, remediations)
    return SerixReport(**report_dict)
