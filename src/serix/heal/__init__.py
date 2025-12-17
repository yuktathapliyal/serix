"""Self-Healing Engine for automatic vulnerability fixes.

Analyzes successful attacks and generates fix suggestions:
- Text fixes: Hardened system prompts with unified diffs
- Tool fixes: Policy and permission recommendations
"""

from serix.heal.analyzer import VulnerabilityAnalyzer
from serix.heal.engine import AttackContext, HealingEngine
from serix.heal.patcher import PromptPatcher
from serix.heal.types import AnalysisResult, HealingResult, TextFix, ToolFix

__all__ = [
    # Main entry point
    "HealingEngine",
    "AttackContext",
    # Result types
    "HealingResult",
    "TextFix",
    "ToolFix",
    "AnalysisResult",
    # Components (for advanced use)
    "VulnerabilityAnalyzer",
    "PromptPatcher",
]
