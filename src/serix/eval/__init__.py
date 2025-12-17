"""Multi-axis security scoring, classification, and remediation."""

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
