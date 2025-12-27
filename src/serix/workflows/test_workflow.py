"""Test workflow for orchestrating security attacks.

Runs attacks against a target using multiple personas in parallel,
collecting results and handling graceful cancellation.

Sprint 2 additions:
- Optional regression check (immune check) before new attacks
- Storage of successful attacks to attack library
- Target ID tracking for persistence

Sprint 3 additions:
- Healing generation for successful attacks
- HTML and JSON report generation
- Campaign directory structure with run_id
"""

from __future__ import annotations

import signal
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.constants import EXIT_ERROR, EXIT_SUCCESS, EXIT_VULNERABLE
from ..core.events import (
    EventListener,
    NullEventListener,
    WorkflowCancelledEvent,
    WorkflowCompletedEvent,
    WorkflowStartedEvent,
)
from ..core.types import AttackResult, WorkflowResult

if TYPE_CHECKING:
    from ..core.target import Target
    from ..fuzz.personas.base import AttackPersona
    from ..services.attack import AttackService
    from ..services.healing import HealingService
    from ..services.regression import RegressionService
    from ..services.report import ReportService
    from ..services.storage import StorageService


class TestWorkflow:
    """Workflow for running security tests against targets.

    Orchestrates:
    1. Setup target
    2. Run regression check (immune check) if enabled
    3. Run attacks with all personas in parallel (ThreadPoolExecutor)
    4. Save successful attacks to storage
    5. Collect results
    6. Handle Ctrl+C gracefully
    7. Teardown and return results

    Events emitted:
    - WorkflowStartedEvent: When workflow begins
    - RegressionStartedEvent/RegressionCompletedEvent: During immune check
    - AttackStartedEvent/AttackCompletedEvent: During attacks
    - WorkflowCompletedEvent: When workflow finishes normally
    - WorkflowCancelledEvent: When interrupted by Ctrl+C
    """

    _cancelled: bool = False

    def __init__(
        self,
        attack_service: "AttackService",
        personas: list["AttackPersona"],
        event_listener: EventListener | None = None,
        max_workers: int = 4,
        # Sprint 2 additions
        storage_service: "StorageService | None" = None,
        regression_service: "RegressionService | None" = None,
        # Sprint 3 additions
        healing_service: "HealingService | None" = None,
        report_service: "ReportService | None" = None,
    ) -> None:
        """Initialize test workflow.

        Args:
            attack_service: Service for executing individual attacks
            personas: List of personas to use
            event_listener: Listener for workflow events
            max_workers: Max parallel persona executions (default: 4)
            storage_service: Service for persisting attacks (optional)
            regression_service: Service for immune check (optional)
            healing_service: Service for generating healing patches (optional)
            report_service: Service for generating reports (optional)
        """
        self._attack = attack_service
        self._personas = personas
        self._events: EventListener = event_listener or NullEventListener()
        self._max_workers = max_workers
        self._original_handler: Any = None
        # Sprint 2 additions
        self._storage = storage_service
        self._regression = regression_service
        # Sprint 3 additions
        self._healing = healing_service
        self._report = report_service

    def run(
        self,
        target: "Target",
        goals: list[str],
        # Sprint 2 additions
        target_id: str | None = None,
        run_regression: bool = True,
        skip_mitigated: bool = False,
        serix_version: str = "",
        # Sprint 3 additions
        generate_healing: bool = True,
        generate_reports: bool = True,
        report_path: Path | None = None,
        depth: int = 5,
        mode: str = "adaptive",
    ) -> WorkflowResult:
        """Run test workflow.

        Executes all persona/goal combinations in parallel using
        ThreadPoolExecutor. Handles Ctrl+C for graceful cancellation.

        Args:
            target: Target to test
            goals: List of attack goals
            target_id: Target identifier for storage (optional)
            run_regression: Run immune check before attacks (default: True)
            skip_mitigated: Skip attacks marked as defended (default: False)
            serix_version: Version string for stored attacks
            generate_healing: Generate healing patches (default: True)
            generate_reports: Generate HTML/JSON reports (default: True)
            report_path: Custom HTML report path (optional)
            depth: Attack depth for report metadata
            mode: Attack mode for report metadata

        Returns:
            WorkflowResult with all attack outcomes and exit code
        """
        start_time = time.perf_counter()
        self._cancelled = False

        # Sprint 3: Generate run_id for campaign directory
        run_id: str | None = None
        if target_id and self._storage:
            run_id = self._storage.generate_run_id()

        # Setup signal handler for graceful cancellation
        self._original_handler = signal.signal(signal.SIGINT, self._handle_sigint)

        # Emit workflow start
        self._events.on_event(
            WorkflowStartedEvent(
                command="test",
                target=str(target),
                goals=goals,
            )
        )

        all_results: list[AttackResult] = []

        try:
            target.setup()

            # Sprint 2: Run regression check (immune check) first
            if run_regression and self._regression and target_id:
                self._regression.run(
                    target,
                    target_id,
                    skip_mitigated=skip_mitigated,
                )

            # Run attacks in parallel using thread pool
            with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                # Submit all persona/goal combinations
                futures: dict[Future[AttackResult], tuple[str, str]] = {}

                for goal in goals:
                    for persona in self._personas:
                        if self._cancelled:
                            break

                        future = executor.submit(
                            self._run_attack,
                            target,
                            goal,
                            persona,
                        )
                        futures[future] = (goal, persona.name)

                    if self._cancelled:
                        break

                # Collect results as they complete
                for future in as_completed(futures):
                    if self._cancelled:
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        break

                    try:
                        result = future.result()
                        all_results.append(result)
                    except Exception as e:
                        goal, persona_name = futures[future]
                        # Create failed result for error
                        all_results.append(
                            AttackResult(
                                success=False,
                                persona=persona_name,
                                goal=goal,
                                turns_taken=0,
                                confidence=0.0,
                                judge_reasoning=f"Error: {e}",
                            )
                        )

        except Exception:
            # Workflow-level error
            duration = time.perf_counter() - start_time
            return WorkflowResult(
                passed=False,
                total_attacks=len(all_results),
                exploited=0,
                defended=0,
                duration_seconds=duration,
                exit_code=EXIT_ERROR,
                attacks=all_results,
            )

        finally:
            target.teardown()
            # Restore original signal handler
            if self._original_handler is not None:
                signal.signal(signal.SIGINT, self._original_handler)

        # Calculate results
        duration = time.perf_counter() - start_time
        exploited = sum(1 for r in all_results if r.success)
        defended = len(all_results) - exploited
        passed = exploited == 0

        # Sprint 2: Save successful attacks to storage
        if self._storage and target_id:
            for result in all_results:
                if result.success and result.winning_payload:
                    try:
                        self._storage.add_attack(
                            target_id=target_id,
                            result=result,
                            strategy_id=result.persona,
                            serix_version=serix_version,
                        )
                    except Exception:
                        # Storage error should not fail workflow
                        pass

        # Sprint 3: Generate healing if exploits found
        healing_result = None
        if generate_healing and self._healing and exploited > 0:
            try:
                # Get target module and function for system prompt heuristic
                target_module = getattr(target, "_module", None)
                target_func = getattr(target, "_func", None)

                healing_result = self._healing.heal(
                    attacks=all_results,
                    target_module=target_module,
                    target_func=target_func,
                )
            except Exception:
                # Healing error should not fail workflow
                pass

        # Sprint 3: Build workflow result early for report generation
        workflow_result = WorkflowResult(
            passed=passed,
            total_attacks=len(all_results),
            exploited=exploited,
            defended=defended,
            duration_seconds=duration,
            exit_code=EXIT_SUCCESS if passed else EXIT_VULNERABLE,
            attacks=all_results,
        )

        # Sprint 3: Generate reports
        if generate_reports and self._report and target_id and run_id:
            try:
                # Generate JSON report
                self._report.generate_json(
                    workflow_result=workflow_result,
                    target_id=target_id,
                    run_id=run_id,
                    target=str(target),
                    healing=healing_result,
                    serix_version=serix_version,
                    depth=depth,
                    mode=mode,
                )

                # Generate HTML report
                self._report.generate_html(
                    workflow_result=workflow_result,
                    target=str(target),
                    output_path=report_path,
                    healing=healing_result,
                    serix_version=serix_version,
                    depth=depth,
                    mode=mode,
                )

                # Save patch if healing available
                if healing_result and healing_result.text_fix:
                    self._report.save_patch(
                        healing=healing_result,
                        target_id=target_id,
                        run_id=run_id,
                    )
            except Exception:
                # Report error should not fail workflow
                pass

        # Determine exit code
        if self._cancelled:
            exit_code = 130  # Standard SIGINT exit code
            self._events.on_event(WorkflowCancelledEvent(command="test"))
            # Update workflow_result with cancellation exit code
            workflow_result = WorkflowResult(
                passed=passed,
                total_attacks=len(all_results),
                exploited=exploited,
                defended=defended,
                duration_seconds=duration,
                exit_code=exit_code,
                attacks=all_results,
            )
        else:
            exit_code = EXIT_SUCCESS if passed else EXIT_VULNERABLE
            self._events.on_event(
                WorkflowCompletedEvent(
                    command="test",
                    total_attacks=len(all_results),
                    exploited=exploited,
                    defended=defended,
                    duration_seconds=duration,
                    exit_code=exit_code,
                )
            )

        return workflow_result

    def _run_attack(
        self,
        target: "Target",
        goal: str,
        persona: "AttackPersona",
    ) -> AttackResult:
        """Run a single attack (called in thread pool).

        Args:
            target: Target to attack
            goal: Attack goal
            persona: Persona to use

        Returns:
            AttackResult from the attack service
        """
        return self._attack.execute(target, goal, persona)

    def _handle_sigint(self, signum: int, frame: object) -> None:
        """Handle Ctrl+C gracefully.

        Sets cancelled flag to stop processing new attacks.
        Running attacks will complete.
        """
        self._cancelled = True
