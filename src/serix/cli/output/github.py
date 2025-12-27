"""GitHub Actions renderer for CI/CD integration.

Outputs:
- ::error:: annotations for successful exploits
- ::warning:: for regressions that still fail
- Job summary written to $GITHUB_STEP_SUMMARY
- Outputs written to $GITHUB_OUTPUT for later steps
"""

from __future__ import annotations

import os
from typing import Any

from ...core.events import (
    AttackCompletedEvent,
    HealingGeneratedEvent,
    HealingStartedEvent,
    RegressionAttackEvent,
    RegressionCompletedEvent,
    RegressionStartedEvent,
    WorkflowCancelledEvent,
    WorkflowCompletedEvent,
    WorkflowStartedEvent,
)


class GithubRenderer:
    """Renderer for GitHub Actions output.

    Outputs:
    - ::error:: annotations for successful exploits
    - ::warning:: for regressions that still fail
    - Job summary to $GITHUB_STEP_SUMMARY
    - Outputs to $GITHUB_OUTPUT
    """

    def __init__(self) -> None:
        """Initialize GitHub renderer."""
        self._exploits: list[dict[str, Any]] = []
        self._regression_still_exploited: int = 0
        self._regression_now_defended: int = 0
        self._total_attacks: int = 0
        self._target: str = ""

    def on_event(self, event: object) -> None:
        """Handle events from workflow."""
        if isinstance(event, WorkflowStartedEvent):
            self._on_workflow_started(event)
        elif isinstance(event, RegressionStartedEvent):
            self._on_regression_started(event)
        elif isinstance(event, RegressionAttackEvent):
            self._on_regression_attack(event)
        elif isinstance(event, RegressionCompletedEvent):
            self._on_regression_completed(event)
        elif isinstance(event, AttackCompletedEvent):
            self._on_attack_completed(event)
        elif isinstance(event, HealingStartedEvent):
            self._on_healing_started(event)
        elif isinstance(event, HealingGeneratedEvent):
            self._on_healing_generated(event)
        elif isinstance(event, WorkflowCompletedEvent):
            self._on_workflow_completed(event)
        elif isinstance(event, WorkflowCancelledEvent):
            self._on_workflow_cancelled(event)

    def _on_workflow_started(self, event: WorkflowStartedEvent) -> None:
        """Handle workflow start - store target for summary."""
        self._target = event.target
        # In GitHub Actions, we're quiet during workflow start
        # Summary is written at the end

    def _on_regression_started(self, event: RegressionStartedEvent) -> None:
        """Handle regression start - log info."""
        print(f"::group::Immune Check ({event.total_attacks} known exploits)")

    def _on_regression_attack(self, event: RegressionAttackEvent) -> None:
        """Handle regression attack result."""
        if event.current_result == "exploited":
            status = "Still exploited"
        else:
            status = "Now defended"

        if event.changed:
            status += " (FIXED!)"

        print(f"  {event.attack_id}: {status}")

    def _on_regression_completed(self, event: RegressionCompletedEvent) -> None:
        """Handle regression completion - emit warning if still exploited."""
        print("::endgroup::")

        self._regression_still_exploited = event.still_exploited
        self._regression_now_defended = event.now_defended

        if event.still_exploited > 0:
            print(
                f"::warning title=Regression Check::"
                f"{event.still_exploited} known exploit(s) still work"
            )

        if event.now_defended > 0:
            print(
                f"::notice title=Regression Check::"
                f"{event.now_defended} vulnerability(ies) fixed!"
            )

    def _on_attack_completed(self, event: AttackCompletedEvent) -> None:
        """Handle attack completion - emit error annotation if successful."""
        self._total_attacks += 1

        if event.success:
            owasp = event.owasp_code or "LLM01"
            print(
                f"::error title=[{owasp}] Exploit Succeeded::"
                f"{event.persona}: {event.goal}"
            )
            self._exploits.append(
                {
                    "persona": event.persona,
                    "goal": event.goal,
                    "owasp_code": event.owasp_code,
                    "confidence": event.confidence,
                }
            )

    def _on_healing_started(self, event: HealingStartedEvent) -> None:
        """Handle healing start - log info."""
        print(
            f"::group::Generating Healing Patch ({event.successful_attacks} exploits)"
        )

    def _on_healing_generated(self, event: HealingGeneratedEvent) -> None:
        """Handle healing generated - close group."""
        print(f"  Vulnerability: {event.vulnerability_type}")
        print(f"  OWASP: {event.owasp_code}")
        print(f"  Confidence: {int(event.confidence * 100)}%")
        print("::endgroup::")

    def _on_workflow_completed(self, event: WorkflowCompletedEvent) -> None:
        """Handle workflow completion - write job summary and outputs."""
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        output_path = os.environ.get("GITHUB_OUTPUT")

        # Write job summary
        if summary_path:
            self._write_summary(summary_path, event)

        # Write outputs
        if output_path:
            self._write_outputs(output_path, event)

        # Print final status
        if event.exploited > 0:
            print(f"::error::Security test FAILED: {event.exploited} exploit(s) found")
        else:
            print("::notice::Security test PASSED: No exploits found")

    def _on_workflow_cancelled(self, event: WorkflowCancelledEvent) -> None:
        """Handle workflow cancellation."""
        print("::warning::Security test was interrupted")

    def _write_summary(self, path: str, event: WorkflowCompletedEvent) -> None:
        """Write markdown to GITHUB_STEP_SUMMARY."""
        status_emoji = ":white_check_mark:" if event.exit_code == 0 else ":x:"
        status = "PASSED" if event.exit_code == 0 else "FAILED"

        lines = [
            "# Serix Security Scan",
            "",
            f"## {status_emoji} {status}",
            "",
        ]

        if self._target:
            lines.append(f"**Target:** `{self._target}`")
            lines.append("")

        lines.extend(
            [
                "| Metric | Value |",
                "|--------|-------|",
                f"| Total Attacks | {event.total_attacks} |",
                f"| Exploited | {event.exploited} |",
                f"| Defended | {event.defended} |",
                f"| Duration | {event.duration_seconds:.1f}s |",
                "",
            ]
        )

        # Regression info if available
        if self._regression_still_exploited > 0 or self._regression_now_defended > 0:
            lines.extend(
                [
                    "### Regression Check (Immune Test)",
                    f"- Still exploited: {self._regression_still_exploited}",
                    f"- Now defended: {self._regression_now_defended}",
                    "",
                ]
            )

        # Exploits found
        if self._exploits:
            lines.extend(
                [
                    "### Vulnerabilities Found",
                    "",
                ]
            )
            for exploit in self._exploits:
                owasp = exploit.get("owasp_code", "LLM01")
                confidence = int(exploit.get("confidence", 0) * 100)
                lines.append(
                    f"- :red_circle: **[{owasp}]** {exploit['persona']}: "
                    f"{exploit['goal']} ({confidence}% confidence)"
                )
            lines.append("")
        else:
            lines.extend(
                [
                    "### No Vulnerabilities Found :tada:",
                    "",
                    "The agent successfully defended against all attack scenarios.",
                    "",
                ]
            )

        try:
            with open(path, "a") as f:
                f.write("\n".join(lines))
                f.write("\n")
        except OSError:
            pass  # Silently fail if can't write

    def _write_outputs(self, path: str, event: WorkflowCompletedEvent) -> None:
        """Write to GITHUB_OUTPUT for use in later steps."""
        try:
            with open(path, "a") as f:
                f.write(f"passed={str(event.exit_code == 0).lower()}\n")
                f.write(f"total_attacks={event.total_attacks}\n")
                f.write(f"exploited={event.exploited}\n")
                f.write(f"defended={event.defended}\n")
                f.write(f"duration={event.duration_seconds:.1f}\n")
                f.write(f"exit_code={event.exit_code}\n")

                # Count vulnerabilities by OWASP code
                owasp_counts: dict[str, int] = {}
                for exploit in self._exploits:
                    code = exploit.get("owasp_code", "LLM01")
                    owasp_counts[code] = owasp_counts.get(code, 0) + 1

                if owasp_counts:
                    owasp_str = ",".join(f"{k}:{v}" for k, v in owasp_counts.items())
                    f.write(f"owasp_codes={owasp_str}\n")
        except OSError:
            pass  # Silently fail if can't write


def is_github_actions() -> bool:
    """Check if running in GitHub Actions.

    Returns:
        True if GITHUB_ACTIONS env var is set to "true"
    """
    return os.environ.get("GITHUB_ACTIONS") == "true"
