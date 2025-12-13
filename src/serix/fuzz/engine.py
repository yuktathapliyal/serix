"""Fuzzing engine that orchestrates mutations."""

from __future__ import annotations

from dataclasses import dataclass, field

from openai.types.chat import ChatCompletion
from rich.console import Console

from serix.core.types import FuzzConfig
from serix.fuzz.mutations import (
    ErrorMutation,
    JsonCorruptionMutation,
    LatencyMutation,
    Mutation,
)

console = Console()


@dataclass
class FuzzResult:
    """Result of a fuzzing run."""

    original_response: ChatCompletion
    mutated_response: ChatCompletion | None
    mutations_applied: list[str] = field(default_factory=list)
    error_raised: Exception | None = None


class FuzzEngine:
    """Orchestrates fuzzing mutations on API responses."""

    def __init__(self, config: FuzzConfig, verbose: bool = False) -> None:
        self.config = config
        self.verbose = verbose
        self.mutations: list[Mutation] = []
        self._setup_mutations()

    def _setup_mutations(self) -> None:
        """Initialize enabled mutations based on config."""
        if self.config.enable_latency:
            self.mutations.append(
                LatencyMutation(delay_seconds=self.config.latency_seconds)
            )

        if self.config.enable_errors:
            self.mutations.append(ErrorMutation(error_codes=self.config.error_codes))

        if self.config.enable_json_corruption:
            self.mutations.append(JsonCorruptionMutation())

    def maybe_mutate(self, response: ChatCompletion) -> FuzzResult:
        """
        Potentially apply mutations to a response.

        Each mutation has a chance to be applied based on mutation_probability.
        Multiple mutations can be applied to the same response.
        """
        result = FuzzResult(
            original_response=response,
            mutated_response=response,
        )

        for mutation in self.mutations:
            if mutation.should_apply(self.config.mutation_probability):
                # Show visible feedback when mutation is applied
                console.print(f"[yellow]⚡ FUZZ:[/yellow] Applying {mutation.name}...")
                try:
                    result.mutated_response = mutation.apply(
                        result.mutated_response,  # type: ignore
                        verbose=self.verbose,
                    )
                    result.mutations_applied.append(mutation.name)
                except Exception as e:
                    # Error mutation raises instead of returning
                    console.print(
                        f"[red]⚡ FUZZ:[/red] {mutation.name} injected error!"
                    )
                    result.error_raised = e
                    result.mutations_applied.append(mutation.name)
                    break  # Stop applying more mutations after error

        return result

    def get_active_mutations(self) -> list[str]:
        """Return names of active mutations."""
        return [m.name for m in self.mutations]
