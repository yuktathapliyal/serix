"""Test workflow orchestration based on TestRunConfig."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from serix.core.run_config import TestRunConfig
    from serix.core.target import Target


@dataclass
class TestResult:
    """Result of a test run."""

    passed: bool
    goals_tested: int
    goals_passed: int
    goals_failed: int
    vulnerabilities_found: int


class TestWorkflow:
    """Orchestrates test execution based on TestRunConfig.

    All behavior is controlled by config flags.
    This is the ONLY place where flag logic is checked.
    """

    def __init__(self, config: TestRunConfig) -> None:
        self.config = config
        self._storage: Any = None
        self._setup_storage()

    def _setup_storage(self) -> None:
        """Setup storage only if dry_run is False."""
        if self.config.should_write_to_disk():
            from serix.regression.store import AttackStore

            self._storage = AttackStore()
        # If dry_run=True, self._storage stays None

    def run(self, target: Target) -> TestResult:
        """Execute the test workflow."""
        # Phase 1: Regression check (if enabled)
        if not self.config.skip_regression and self._storage:
            self._run_regression_check(target)

        # Phase 2: Security testing (if enabled)
        results: Any = None
        if self.config.should_run_security_tests():
            results = self._run_security_tests(target)
        # fuzz_only skips this

        # Phase 3: Fuzzing (if enabled)
        if self.config.fuzz_enabled:
            self._run_fuzzing(target)

        # Phase 4: Save results (if not dry_run)
        if self.config.should_write_to_disk() and results:
            self._save_results(results)

        # Phase 5: Generate report (if enabled)
        if self.config.should_generate_report() and results:
            self._generate_report(results)

        # Phase 6: Generate patches (if enabled)
        if self.config.should_generate_patches() and results:
            self._generate_patches(results)

        return self._build_result(results)

    def _run_regression_check(self, target: Target) -> None:
        """Run immune check against stored attacks."""
        pass  # TODO: Implement in Phase 5

    def _run_security_tests(self, target: Target) -> Any:
        """Run security testing (static or adaptive)."""
        pass  # TODO: Implement in Phase 5

    def _run_fuzzing(self, target: Target) -> None:
        """Run fuzzing mutations."""
        pass  # TODO: Implement in Phase 5

    def _save_results(self, results: Any) -> None:
        """Save attack results to storage."""
        if self._storage is None:
            return  # dry_run mode
        pass  # TODO: Implement in Phase 5

    def _generate_report(self, results: Any) -> None:
        """Generate HTML/JSON report."""
        pass  # TODO: Implement in Phase 5

    def _generate_patches(self, results: Any) -> None:
        """Generate healing patches."""
        pass  # TODO: Implement in Phase 5

    def _build_result(self, results: Any) -> TestResult:
        """Build final test result."""
        return TestResult(
            passed=True,
            goals_tested=0,
            goals_passed=0,
            goals_failed=0,
            vulnerabilities_found=0,
        )
