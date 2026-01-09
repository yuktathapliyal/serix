"""
Serix v2 - Chaos Injection Service

Probabilistic chaos injection for `serix dev --fuzz`.
Wraps a Target with random mutations (latency, errors, JSON corruption).

Architecture: Decorator Pattern
- ChaosInjector.wrap(target) returns ChaosTarget
- ChaosTarget implements Target protocol but adds probabilistic mutations

Law Compliance:
- Law 2: No typer/rich/click imports (pure Python)
- Law 3: Depends on Target protocol, not concrete classes
- Law 4: All state in instances, no module globals

Reference: Phase 9D Plan, fuzzing-architecture-spec.md
"""

from __future__ import annotations

import random
import time
from typing import TYPE_CHECKING, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from serix_v2.core.config import SerixSessionConfig
    from serix_v2.core.protocols import Target


# ============================================================================
# CHAOS ERROR
# ============================================================================


class ChaosError(Exception):
    """
    Raised by ErrorMutation to simulate API failures.

    Integrates with AttackTurn.error_type from Phase 6 hardening.
    When caught, the error_code can be used for reporting.

    Attributes:
        error_code: HTTP-like status code (500, 503, 429)
        message: Error description
    """

    def __init__(self, error_code: int, message: str) -> None:
        self.error_code = error_code
        super().__init__(message)

    def __str__(self) -> str:
        return f"ChaosError(HTTP {self.error_code}): {super().__str__()}"


# ============================================================================
# CHAOS CONFIG
# ============================================================================


class ChaosConfig(BaseModel):
    """
    Configuration for probabilistic chaos injection.

    Used by ChaosInjector to determine which mutations to apply
    and with what probability.
    """

    probability: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Probability of applying mutation per call (0.0-1.0)",
    )
    latency_enabled: bool = Field(
        default=False,
        description="Enable latency injection",
    )
    latency_seconds: float = Field(
        default=5.0,
        gt=0.0,
        description="Delay in seconds when latency mutation is applied",
    )
    errors_enabled: bool = Field(
        default=False,
        description="Enable HTTP-like error injection",
    )
    json_enabled: bool = Field(
        default=False,
        description="Enable JSON corruption injection",
    )
    random_seed: Optional[int] = Field(
        default=None,
        description="Seed for deterministic testing (Deterministic Chaos)",
    )

    @classmethod
    def from_session_config(cls, config: "SerixSessionConfig") -> "ChaosConfig":
        """
        Create ChaosConfig from SerixSessionConfig.

        Maps --fuzz-* CLI flags to ChaosConfig fields.

        Args:
            config: Session configuration with fuzz flags

        Returns:
            ChaosConfig with appropriate settings
        """
        return cls(
            probability=config.fuzz_probability,
            latency_enabled=config.fuzz_latency is not None or config.fuzz,
            latency_seconds=config.get_effective_fuzz_latency(),
            errors_enabled=config.fuzz_errors or config.fuzz,
            json_enabled=config.fuzz_json or config.fuzz,
        )


# ============================================================================
# MUTATION PROTOCOL
# ============================================================================


@runtime_checkable
class Mutation(Protocol):
    """
    Protocol for chaos mutations.

    Implementations can extend this for custom mutations (e.g., PIILeakMutation).
    Runtime checkable for isinstance() verification.
    """

    @property
    def name(self) -> str:
        """Mutation identifier (e.g., 'latency', 'error', 'json')."""
        ...

    def apply(self, message: str, target: "Target", rng: random.Random) -> str:
        """
        Apply mutation and return result.

        Args:
            message: Original message to send to target
            target: The wrapped target (for calling through)
            rng: Random number generator for deterministic behavior

        Returns:
            Response string (may be from target or corrupted)

        Raises:
            ChaosError: For error injection
        """
        ...


# ============================================================================
# MUTATION IMPLEMENTATIONS
# ============================================================================


class LatencyMutation:
    """
    Inject artificial latency before target call.

    NOTE: This mutation DOES call target (passthrough after delay).
    Simulates slow API, not total failure.
    """

    def __init__(self, delay_seconds: float = 5.0) -> None:
        self._delay = delay_seconds

    @property
    def name(self) -> str:
        return "latency"

    def apply(self, message: str, target: "Target", rng: random.Random) -> str:
        """Sleep, then call target normally."""
        time.sleep(self._delay)
        return target(message)


class ErrorMutation:
    """
    Inject HTTP-like errors instead of calling target.

    NOTE: This mutation does NOT call target (skip to save tokens).
    Simulates total API failure.
    """

    DEFAULT_ERROR_CODES = [500, 503, 429]

    def __init__(self, error_codes: list[int] | None = None) -> None:
        self._error_codes = error_codes or self.DEFAULT_ERROR_CODES

    @property
    def name(self) -> str:
        return "error"

    def apply(self, message: str, target: "Target", rng: random.Random) -> str:
        """Raise ChaosError with random error code. Does NOT call target."""
        error_code = rng.choice(self._error_codes)
        error_messages = {
            500: "Internal Server Error (injected by Serix Chaos)",
            503: "Service Unavailable (injected by Serix Chaos)",
            429: "Rate Limit Exceeded (injected by Serix Chaos)",
        }
        raise ChaosError(
            error_code=error_code,
            message=error_messages.get(error_code, f"HTTP {error_code} Error"),
        )


class JsonMutation:
    """
    Return corrupted JSON response instead of calling target.

    NOTE: This mutation does NOT call target (skip to save tokens).
    Simulates malformed API response.

    Hybrid approach: Structured corruption + empty baseline.
    """

    CORRUPTION_PAYLOADS = [
        '{"key": "value"',  # Unclosed object (simulates token limit)
        "[1, 2,",  # Unclosed array (network cut mid-stream)
        '{"count": "not_a_number"}',  # Wrong type (schema violation)
        "",  # Empty string (connection drop baseline)
    ]

    @property
    def name(self) -> str:
        return "json"

    def apply(self, message: str, target: "Target", rng: random.Random) -> str:
        """Return random corrupted payload. Does NOT call target."""
        return rng.choice(self.CORRUPTION_PAYLOADS)


# ============================================================================
# CHAOS INJECTOR
# ============================================================================


class ChaosInjector:
    """
    Wraps a Target with probabilistic chaos injection.

    Usage:
        config = ChaosConfig(probability=0.5, latency_enabled=True)
        injector = ChaosInjector(config)
        chaos_target = injector.wrap(original_target)
        result = chaos_target("Hello")  # May have chaos applied

    Law Compliance:
        - Law 2: No typer/rich/click imports
        - Law 3: Depends on Target protocol
    """

    def __init__(self, config: ChaosConfig) -> None:
        """
        Initialize with chaos configuration.

        Args:
            config: ChaosConfig with enabled mutations and probability
        """
        self._config = config
        self._rng = random.Random(config.random_seed)
        self._mutations = self._build_mutations()

    def _build_mutations(self) -> list[Mutation]:
        """Build list of enabled mutations based on config."""
        mutations: list[Mutation] = []

        if self._config.latency_enabled:
            mutations.append(LatencyMutation(self._config.latency_seconds))

        if self._config.errors_enabled:
            mutations.append(ErrorMutation())

        if self._config.json_enabled:
            mutations.append(JsonMutation())

        return mutations

    def wrap(self, target: "Target") -> "ChaosTarget":
        """
        Wrap a target with chaos injection.

        Args:
            target: Original Target to wrap

        Returns:
            ChaosTarget that applies probabilistic mutations
        """
        return ChaosTarget(target=target, injector=self)

    def _should_apply_chaos(self) -> bool:
        """Roll dice to determine if chaos should be applied this call."""
        return self._rng.random() < self._config.probability

    def _select_mutation(self) -> Mutation | None:
        """Select a random mutation from enabled mutations."""
        if not self._mutations:
            return None
        return self._rng.choice(self._mutations)

    @property
    def mutations(self) -> list[Mutation]:
        """Get the list of enabled mutations (for testing)."""
        return self._mutations

    @property
    def rng(self) -> random.Random:
        """Get the random number generator (for mutations)."""
        return self._rng


# ============================================================================
# CHAOS TARGET
# ============================================================================


class ChaosTarget:
    """
    Target wrapper that applies probabilistic mutations.

    Implements Target protocol but adds chaos.
    Delegates id and locator to wrapped target.
    """

    def __init__(self, target: "Target", injector: ChaosInjector) -> None:
        self._target = target
        self._injector = injector

    @property
    def id(self) -> str:
        """Delegate to wrapped target."""
        return self._target.id

    @property
    def locator(self) -> str:
        """Delegate to wrapped target."""
        return self._target.locator

    @property
    def unwrapped(self) -> "Target":
        """
        Access the underlying Target without chaos.

        Use this when DevWorkflow needs original target metadata
        for logging/reporting without triggering mutations.
        """
        return self._target

    def __call__(self, message: str) -> str:
        """
        Call target with possible chaos injection.

        On each call:
        1. Roll dice against probability
        2. If hit, select random enabled mutation
        3. Apply mutation (may delay, raise error, or corrupt)
        4. If no mutation or dice miss, call target normally
        """
        if self._injector._should_apply_chaos():
            mutation = self._injector._select_mutation()
            if mutation is not None:
                return mutation.apply(message, self._target, self._injector.rng)

        # No chaos applied - call target normally
        return self._target(message)
