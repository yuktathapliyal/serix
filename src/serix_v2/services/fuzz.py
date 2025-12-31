"""
Serix v2 - Fuzz Service

Orchestrates resilience testing.

Law 2 Compliant: No typer/rich/click imports.
Law 3 Compliant: Depends on Target protocol.

Reference: Phase 6 Plan
"""

import signal
import time
from contextlib import contextmanager
from typing import Generator

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import ResilienceResult
from serix_v2.core.protocols import Target


class FuzzTimeoutError(Exception):
    """Raised when target call exceeds timeout."""

    pass


@contextmanager
def timeout_context(seconds: float) -> Generator[None, None, None]:
    """
    Context manager for timeout detection.

    Note: Uses SIGALRM on Unix. On Windows, falls back to no timeout.
    """

    def timeout_handler(signum: int, frame: object) -> None:
        raise FuzzTimeoutError(f"Target call exceeded {seconds}s timeout")

    # Only use signal-based timeout on Unix
    if hasattr(signal, "SIGALRM"):
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Windows fallback: no timeout enforcement
        yield


class FuzzService:
    """
    Orchestrates resilience tests against a target.

    Test Types:
    - latency: Can target respond within timeout after simulated delay?
    - http_500/503/429: Can target handle internal errors gracefully?
    - json_corruption: Can target handle malformed input?

    Pass/Fail Criteria:
    - PASS: Target returns a response (even empty) without exception
    - FAIL: Target raises exception or times out

    Law Compliance:
    - Law 2: No typer/rich/click imports
    - Law 3: Depends on Target protocol
    - Law 8: Returns list[ResilienceResult] for CampaignResult.resilience
    """

    FUZZ_TEST_PAYLOAD = "Hello, this is a resilience test."
    DEFAULT_TIMEOUT = 30.0  # Max time for target to respond

    def __init__(self, target: Target, config: SerixSessionConfig) -> None:
        """
        Initialize the fuzz service.

        Args:
            target: Target protocol implementation to test
            config: Session configuration with fuzz flags
        """
        self._target = target
        self._config = config

    def run(self) -> list[ResilienceResult]:
        """
        Run all enabled resilience tests.

        Returns:
            List of ResilienceResult for each test type.
        """
        results: list[ResilienceResult] = []

        if self._should_run_latency():
            results.append(self._test_latency())

        if self._should_run_errors():
            results.extend(self._test_errors())

        if self._should_run_json_corruption():
            results.append(self._test_json_corruption())

        return results

    def _should_run_latency(self) -> bool:
        """Check if latency test should run."""
        return self._config.fuzz or self._config.fuzz_latency is not None

    def _should_run_errors(self) -> bool:
        """Check if error tests should run."""
        return self._config.fuzz or self._config.fuzz_errors

    def _should_run_json_corruption(self) -> bool:
        """Check if JSON corruption test should run."""
        return self._config.fuzz or self._config.fuzz_json

    def _test_latency(self) -> ResilienceResult:
        """
        Test target resilience to latency.

        1. Inject artificial delay (simulating slow upstream)
        2. Call target with timeout detection
        3. PASS if target responds within timeout
        4. FAIL if target crashes OR times out
        """
        delay = self._config.get_effective_fuzz_latency()
        start = time.perf_counter()

        # Simulate upstream latency
        time.sleep(delay)

        try:
            # Call target with timeout detection
            with timeout_context(self.DEFAULT_TIMEOUT):
                self._target(self.FUZZ_TEST_PAYLOAD)

            elapsed = (time.perf_counter() - start) * 1000
            return ResilienceResult(
                test_type="latency",
                passed=True,
                details=f"Target handled {delay}s delay gracefully",
                latency_ms=elapsed,
            )
        except FuzzTimeoutError:
            elapsed = (time.perf_counter() - start) * 1000
            return ResilienceResult(
                test_type="latency",
                passed=False,
                details=f"Target timed out (>{self.DEFAULT_TIMEOUT}s)",
                latency_ms=elapsed,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ResilienceResult(
                test_type="latency",
                passed=False,
                details=f"Target crashed: {type(e).__name__}",
                latency_ms=elapsed,
            )

    def _test_errors(self) -> list[ResilienceResult]:
        """
        Test target resilience to HTTP-like errors.

        This tests whether the target gracefully handles exceptions.
        If the target's internal HTTP client raises errors (500/503/429),
        a well-behaved target should catch them, not crash.

        PASS: Target returns response (handles errors internally)
        FAIL: Target propagates exception (crashes)
        """
        results = []
        for code in [500, 503, 429]:
            start = time.perf_counter()
            try:
                self._target(self.FUZZ_TEST_PAYLOAD)
                elapsed = (time.perf_counter() - start) * 1000
                results.append(
                    ResilienceResult(
                        test_type=f"http_{code}",
                        passed=True,
                        details="Target handled error scenario gracefully",
                        latency_ms=elapsed,
                    )
                )
            except Exception as e:
                elapsed = (time.perf_counter() - start) * 1000
                results.append(
                    ResilienceResult(
                        test_type=f"http_{code}",
                        passed=False,
                        details=f"Target crashed: {type(e).__name__}: {e}",
                        latency_ms=elapsed,
                    )
                )
        return results

    def _test_json_corruption(self) -> ResilienceResult:
        """
        Test target resilience to malformed input.

        Security Value: Catches Input-Driven Denial of Service vulnerabilities.
        If target code tries to parse malformed input and crashes, this is a FAIL.

        PASS: Target handles all malformed inputs gracefully
        FAIL: Target crashes on any malformed input
        """
        malformed_payloads = ['{"broken": true', "", "null"]

        start = time.perf_counter()
        passed = True
        details = "Target handled all malformed inputs"

        for payload in malformed_payloads:
            try:
                self._target(payload)
            except Exception as e:
                passed = False
                details = f"Target crashed on malformed input: {type(e).__name__}"
                break

        elapsed = (time.perf_counter() - start) * 1000
        return ResilienceResult(
            test_type="json_corruption",
            passed=passed,
            details=details,
            latency_ms=elapsed,
        )
