"""Evaluation module - multi-axis security scoring and remediation.

This module provides:
- Multi-axis evaluation scoring (safety, compliance, information leakage, role adherence)
- OWASP-style vulnerability classification with severity levels
- Remediation suggestions with code examples
- Configurable rubrics for different use cases
"""

from serix.eval.classifier import (
    VULNERABILITY_DEFINITIONS,
    Severity,
    VulnerabilityCategory,
    VulnerabilityClassifier,
    VulnerabilityDefinition,
)
from serix.eval.evaluator import (
    EvaluationResult,
    EvaluationScore,
    Evaluator,
    Vulnerability,
)
from serix.eval.remediation import REMEDIATION_TEMPLATES, Remediation, RemediationEngine
from serix.eval.rubric import AxisName, EvaluationRubric, PassThreshold, RubricAxis

__all__ = [
    # Rubric
    "AxisName",
    "RubricAxis",
    "PassThreshold",
    "EvaluationRubric",
    # Classifier
    "Severity",
    "VulnerabilityCategory",
    "VulnerabilityClassifier",
    "VulnerabilityDefinition",
    "VULNERABILITY_DEFINITIONS",
    # Evaluator
    "Evaluator",
    "EvaluationResult",
    "EvaluationScore",
    "Vulnerability",
    # Remediation
    "Remediation",
    "RemediationEngine",
    "REMEDIATION_TEMPLATES",
]
