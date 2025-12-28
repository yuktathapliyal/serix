"""
Serix v2 - Protocol Definitions

Law 3: Depend on interfaces, not implementations.

All external dependencies (LLM, Target, Storage) are defined as Protocols.
The engine ONLY depends on these protocols, never concrete classes.

Reference: Developer Checklist, Law 3
"""

from typing import Protocol, runtime_checkable

from .contracts import (
    AttackLibrary,
    AttackTurn,
    CampaignResult,
    CriticFeedback,
    HealingResult,
    JudgeVerdict,
    StoredAttack,
    VulnerabilityAnalysis,
)

# ============================================================================
# TARGET PROTOCOL
# ============================================================================


@runtime_checkable
class Target(Protocol):
    """
    Protocol for anything that can be attacked.

    Implementations:
    - PythonFunctionTarget (loads a Python function)
    - HTTPTarget (calls an HTTP endpoint)
    """

    @property
    def id(self) -> str:
        """Unique identifier for this target."""
        ...

    @property
    def locator(self) -> str:
        """Original locator string (e.g., 'agent.py:fn' or 'http://...')."""
        ...

    def __call__(self, message: str) -> str:
        """Send a message to the target and get a response."""
        ...


# ============================================================================
# LLM-POWERED COMPONENT PROTOCOLS
# ============================================================================


@runtime_checkable
class Attacker(Protocol):
    """
    Protocol for attack payload generation.

    Implementations: JailbreakerPersona, ExtractorPersona, etc.
    """

    def generate(
        self,
        goal: str,
        history: list[AttackTurn],
    ) -> str:
        """Generate the next attack payload based on goal and conversation history."""
        ...


@runtime_checkable
class Critic(Protocol):
    """
    Protocol for per-turn coaching (adaptive mode).

    The Critic advises whether to continue attacking and how to pivot.
    It does NOT determine if an attack succeeded.
    """

    def evaluate(
        self,
        goal: str,
        turns: list[AttackTurn],
    ) -> CriticFeedback:
        """Evaluate the conversation and provide feedback."""
        ...


@runtime_checkable
class Judge(Protocol):
    """
    Protocol for final attack verdict.

    The Judge determines if an attack succeeded (EXPLOITED) or failed (DEFENDED).
    """

    def evaluate(
        self,
        goal: str,
        payload: str,
        response: str,
    ) -> JudgeVerdict:
        """Evaluate if the attack succeeded."""
        ...


@runtime_checkable
class Analyzer(Protocol):
    """
    Protocol for vulnerability classification.

    Maps successful attacks to OWASP codes and root causes.
    """

    def analyze(
        self,
        goal: str,
        payload: str,
        response: str,
    ) -> VulnerabilityAnalysis:
        """Classify the vulnerability."""
        ...


@runtime_checkable
class Patcher(Protocol):
    """
    Protocol for healing/fix generation.

    Generates patched system prompts based on successful attacks.
    """

    def heal(
        self,
        original_prompt: str,
        attacks: list[tuple[str, str]],  # [(payload, response), ...]
        analysis: VulnerabilityAnalysis,
    ) -> HealingResult:
        """Generate a healing patch."""
        ...


# ============================================================================
# LLM PROVIDER PROTOCOL
# ============================================================================


@runtime_checkable
class LLMProvider(Protocol):
    """
    Protocol for LLM completion.

    Implementations: OpenAIProvider, AnthropicProvider, LiteLLMProvider
    """

    def complete(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float = 0.7,
    ) -> str:
        """Send messages to LLM and get completion."""
        ...


# ============================================================================
# STORAGE PROTOCOLS
# ============================================================================


@runtime_checkable
class AttackStore(Protocol):
    """
    Protocol for attack library persistence.
    """

    def load(self, target_id: str) -> AttackLibrary:
        """Load attack library for a target."""
        ...

    def save(self, library: AttackLibrary) -> None:
        """Save attack library."""
        ...

    def add_attack(self, attack: StoredAttack) -> None:
        """Add or update an attack in the library."""
        ...


@runtime_checkable
class CampaignStore(Protocol):
    """
    Protocol for campaign result persistence.
    """

    def save(self, result: CampaignResult) -> str:
        """Save campaign result and return the run_id."""
        ...

    def load(self, target_id: str, run_id: str) -> CampaignResult:
        """Load a specific campaign result."""
        ...
