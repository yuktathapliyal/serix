"""
Serix v2 - Session Configuration

This is the UNIVERSAL INPUT to all workflows. Every CLI flag maps to a field here.

Law 5: Every flag must map to a code branch.

Reference: Spec 1.8 (CLI <-> Config Mapping), Developer Checklist
"""

from typing import Optional

from pydantic import BaseModel, Field

from . import constants
from .contracts import AttackMode


class SerixSessionConfig(BaseModel):
    """
    Complete configuration for a Serix session.

    Priority: CLI flags > config file > defaults (handled by config_resolver)

    This model is passed to workflows. Workflows never read CLI args directly.
    """

    # ========================================================================
    # TARGET IDENTITY (Spec 02)
    # ========================================================================
    target_path: str  # Required: "agent.py:fn" or "http://..."
    target_name: Optional[str] = None  # --name (stable alias)
    target_id: Optional[str] = None  # --target-id (explicit override)

    # HTTP target options (only used if target is URL)
    input_field: str = constants.DEFAULT_INPUT_FIELD  # --input-field
    output_field: str = constants.DEFAULT_OUTPUT_FIELD  # --output-field
    headers: dict[str, str] = Field(default_factory=dict)  # --headers
    headers_file: Optional[str] = None  # --headers-file

    # ========================================================================
    # ATTACK CONFIG (Spec 1.1)
    # ========================================================================
    goals: list[str] = Field(
        default_factory=lambda: [constants.DEFAULT_GOAL]
    )  # --goal (repeatable)
    goals_file: Optional[str] = None  # --goals-file
    mode: AttackMode = AttackMode.ADAPTIVE  # --mode
    scenarios: list[str] = Field(
        default_factory=lambda: constants.DEFAULT_SCENARIOS.copy()
    )  # --scenarios
    depth: int = constants.DEFAULT_DEPTH  # --depth
    exhaustive: bool = False  # --exhaustive

    # ========================================================================
    # MODELS (Spec 1.8)
    # ========================================================================
    attacker_model: str = constants.DEFAULT_ATTACKER_MODEL  # --attacker-model
    judge_model: str = constants.DEFAULT_JUDGE_MODEL  # --judge-model
    critic_model: str = constants.DEFAULT_CRITIC_MODEL  # --critic-model
    patcher_model: str = constants.DEFAULT_PATCHER_MODEL  # --patcher-model
    analyzer_model: str = constants.DEFAULT_ANALYZER_MODEL  # --analyzer-model

    # ========================================================================
    # FUZZ / RESILIENCE (Spec 1.7)
    # ========================================================================
    fuzz: bool = False  # --fuzz
    fuzz_only: bool = False  # --fuzz-only
    fuzz_latency: Optional[float] = None  # --fuzz-latency [SECS]
    fuzz_errors: bool = False  # --fuzz-errors
    fuzz_json: bool = False  # --fuzz-json
    fuzz_probability: float = constants.DEFAULT_FUZZ_PROBABILITY  # --fuzz-probability

    # ========================================================================
    # REGRESSION (Spec 1.15)
    # ========================================================================
    skip_regression: bool = False  # --skip-regression
    skip_mitigated: bool = False  # --skip-mitigated

    # ========================================================================
    # REPORTING (Spec 1.2)
    # ========================================================================
    report_path: str = constants.DEFAULT_REPORT_PATH  # --report
    no_report: bool = False  # --no-report
    dry_run: bool = False  # --dry-run
    github: bool = False  # --github

    # ========================================================================
    # HEALING (Spec 1.9)
    # ========================================================================
    no_patch: bool = False  # --no-patch
    system_prompt: Optional[str] = None  # For patch generation

    # ========================================================================
    # BEHAVIOR
    # ========================================================================
    live: bool = False  # --live
    verbose: bool = False  # --verbose
    yes: bool = False  # --yes

    # ========================================================================
    # HELPER METHODS (Law 5: Flag-to-Logic mapping)
    # ========================================================================

    def should_write_to_disk(self) -> bool:
        """Returns False if --dry-run is set."""
        return not self.dry_run

    def should_run_security_tests(self) -> bool:
        """Returns False if --fuzz-only is set."""
        return not self.fuzz_only

    def should_run_regression(self) -> bool:
        """Returns False if --skip-regression or --fuzz-only is set."""
        return not self.skip_regression and not self.fuzz_only

    def should_run_fuzz_tests(self) -> bool:
        """Returns True if any fuzz flag is enabled."""
        return (
            self.fuzz
            or self.fuzz_only
            or self.fuzz_latency is not None
            or self.fuzz_errors
            or self.fuzz_json
        )

    def should_generate_report(self) -> bool:
        """Returns False if --no-report or --dry-run is set."""
        return not self.no_report and not self.dry_run

    def should_generate_patch(self) -> bool:
        """Returns False if --no-patch is set or no system_prompt provided."""
        return not self.no_patch and self.system_prompt is not None

    def is_interactive(self) -> bool:
        """Returns False if --yes or --github is set."""
        return not self.yes and not self.github

    def get_effective_fuzz_latency(self) -> float:
        """Returns fuzz latency, using default if flag was set without value."""
        if self.fuzz_latency is not None:
            return self.fuzz_latency
        return constants.DEFAULT_FUZZ_LATENCY
