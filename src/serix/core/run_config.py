"""Single source of truth for all test run configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TestRunConfig:
    """Single source of truth for ALL test run configuration.

    Every CLI flag maps to exactly one field here.
    Every component reads from this config.
    """

    # === Target Configuration ===
    target: str = ""
    target_id: str | None = None  # --target-id: Override auto-generated ID
    name: str | None = None  # --name: Stable alias for target

    # === P1: Safety Flags (Skip Operations) ===
    dry_run: bool = False  # --dry-run: Skip ALL disk writes
    fuzz_only: bool = False  # --fuzz-only: Skip security testing entirely
    no_report: bool = False  # --no-report: Skip report generation
    no_patch: bool = False  # --no-patch: Skip patch generation

    # === P2: Model Selection ===
    attacker_model: str = "gpt-4o-mini"  # --attacker-model
    judge_model: str = "gpt-4o"  # --judge-model
    critic_model: str = "gpt-4o-mini"  # --critic-model
    patcher_model: str = "gpt-4o"  # --patcher-model
    analyzer_model: str = "gpt-4o-mini"  # --analyzer-model

    # === P3: Behavior Flags ===
    exhaustive: bool = False  # --exhaustive: Continue after first exploit
    skip_regression: bool = False  # --skip-regression: Skip immune check

    # === Attack Configuration ===
    mode: str = "adaptive"  # --mode: 'static' or 'adaptive'
    depth: int = 3  # --depth: Turns per persona
    goals: list[str] = field(default_factory=list)
    scenarios: list[str] | None = None

    # === Fuzz Configuration ===
    fuzz_enabled: bool = False
    fuzz_latency: bool = False
    fuzz_errors: bool = False
    fuzz_json: bool = False
    fuzz_probability: float = 0.5

    # === Output Configuration ===
    report_path: Path | None = None  # --report
    verbose: bool = False  # --verbose
    github: bool = False  # --github
    live: bool = False  # --live
    yes: bool = False  # --yes

    # === HTTP Target Configuration ===
    input_field: str = "message"
    output_field: str = "response"
    headers: dict[str, Any] = field(default_factory=dict)

    def should_write_to_disk(self) -> bool:
        """Check if any disk writes are allowed."""
        return not self.dry_run

    def should_run_security_tests(self) -> bool:
        """Check if security testing should run."""
        return not self.fuzz_only

    def should_generate_report(self) -> bool:
        """Check if report generation should run."""
        return not self.no_report and self.report_path is not None

    def should_generate_patches(self) -> bool:
        """Check if patch generation should run."""
        return not self.no_patch
