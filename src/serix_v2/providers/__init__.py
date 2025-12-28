"""
Serix v2 - Provider Implementations

Concrete implementations of LLM providers:
- LiteLLMProvider (multi-provider: OpenAI, Anthropic, Ollama, etc.)

Law 3: These implementations satisfy the LLMProvider protocol from core/protocols.py
"""

from serix_v2.providers.llm.litellm_provider import LiteLLMProvider

__all__ = [
    "LiteLLMProvider",
]
