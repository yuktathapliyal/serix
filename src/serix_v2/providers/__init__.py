"""
Serix v2 - Provider Implementations

Concrete implementations of protocols from core/protocols.py:
- LiteLLMProvider (multi-provider LLM: OpenAI, Anthropic, Ollama, etc.)
- Attackers (JailbreakerAttacker, ExtractorAttacker, etc.)
- LLMJudge (final attack verdict)
- LLMCritic (per-turn tactical coaching)
- LLMAnalyzer (vulnerability classification)

Law 3: All implementations satisfy their respective protocols.
"""

from serix_v2.providers.analyzer import LLMAnalyzer

# Attackers
from serix_v2.providers.attackers import (
    BaseAttacker,
    ConfuserAttacker,
    ExtractorAttacker,
    JailbreakerAttacker,
    ManipulatorAttacker,
    create_attacker,
)
from serix_v2.providers.critic import LLMCritic

# Evaluators
from serix_v2.providers.judge import LLMJudge
from serix_v2.providers.llm.litellm_provider import LiteLLMProvider

# Patcher
from serix_v2.providers.patcher import LLMPatcher
from serix_v2.providers.utils import extract_json_payload

__all__ = [
    # LLM Provider
    "LiteLLMProvider",
    # Utilities
    "extract_json_payload",
    # Attackers
    "BaseAttacker",
    "ConfuserAttacker",
    "ExtractorAttacker",
    "JailbreakerAttacker",
    "ManipulatorAttacker",
    "create_attacker",
    # Evaluators
    "LLMJudge",
    "LLMCritic",
    "LLMAnalyzer",
    # Patcher
    "LLMPatcher",
]
