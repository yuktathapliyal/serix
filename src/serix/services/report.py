"""Report generation service.

Generates HTML and JSON reports from workflow results:
- HTML report: `serix-report.html` in cwd (or custom path)
- JSON report: `.serix/targets/<id>/campaigns/<run_id>/results.json`
- Patch file: `.serix/targets/<id>/campaigns/<run_id>/patch.diff`

Uses atomic writes via StorageService to prevent file corruption.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, PackageLoader, select_autoescape

from ..core.constants import (
    CAMPAIGNS_DIR,
    DEFAULT_REPORT_FILENAME,
    PATCH_FILENAME,
    RESULTS_FILENAME,
    RESULTS_SCHEMA_VERSION,
)

if TYPE_CHECKING:
    from ..core.types import AttackResult, WorkflowResult
    from ..heal.types import HealingResult
    from .storage import StorageService


class ReportService:
    """Service for generating HTML and JSON reports.

    Generates:
    - HTML report: `serix-report.html` in cwd (or custom path)
    - JSON report: `.serix/targets/<id>/campaigns/<run_id>/results.json`
    - Patch file: `.serix/targets/<id>/campaigns/<run_id>/patch.diff`

    Uses atomic writes via StorageService to prevent file corruption.
    """

    def __init__(
        self,
        storage_service: "StorageService | None" = None,
        storage_base: Path | None = None,
        dry_run: bool = False,
    ) -> None:
        """Initialize report service.

        Args:
            storage_service: StorageService for atomic writes (optional)
            storage_base: Base path for .serix/ (default: cwd/.serix)
            dry_run: If True, skip all file writes
        """
        self._storage = storage_service
        self._storage_base = storage_base or Path.cwd() / ".serix"
        self._dry_run = dry_run

    def generate_json(
        self,
        workflow_result: "WorkflowResult",
        target_id: str,
        run_id: str,
        target: str,
        healing: "HealingResult | None" = None,
        serix_version: str = "",
        depth: int = 5,
        mode: str = "adaptive",
    ) -> Path | None:
        """Generate JSON report in campaign directory.

        Args:
            workflow_result: Results from test workflow
            target_id: Target identifier for storage path
            run_id: Campaign run ID
            target: Target locator string
            healing: Optional healing result
            serix_version: Version string
            depth: Attack depth
            mode: Attack mode

        Returns:
            Path to generated JSON, or None if dry run
        """
        if self._dry_run:
            return None

        # Build output path
        campaign_dir = (
            self._storage_base / "targets" / target_id / CAMPAIGNS_DIR / run_id
        )
        campaign_dir.mkdir(parents=True, exist_ok=True)
        output_path = campaign_dir / RESULTS_FILENAME

        # Build JSON data
        data = self._build_json_data(
            workflow_result=workflow_result,
            target=target,
            healing=healing,
            serix_version=serix_version,
            depth=depth,
            mode=mode,
        )

        # Write file atomically
        self._atomic_write(output_path, json.dumps(data, indent=2, default=str))

        return output_path

    def generate_html(
        self,
        workflow_result: "WorkflowResult",
        target: str,
        output_path: Path | None = None,
        healing: "HealingResult | None" = None,
        serix_version: str = "",
        depth: int = 5,
        mode: str = "adaptive",
    ) -> Path | None:
        """Generate HTML report.

        Args:
            workflow_result: Results from test workflow
            target: Target identifier string
            output_path: Custom output path (default: serix-report.html)
            healing: Optional healing result for patch display
            serix_version: Version string
            depth: Attack depth setting
            mode: Attack mode (adaptive/static)

        Returns:
            Path to generated report, or None if dry run
        """
        if self._dry_run:
            return None

        output_path = output_path or Path(DEFAULT_REPORT_FILENAME)

        # Build report data
        report_data = self._build_html_data(
            workflow_result=workflow_result,
            target=target,
            healing=healing,
            serix_version=serix_version,
            depth=depth,
            mode=mode,
        )

        # Render template
        env = Environment(
            loader=PackageLoader("serix.report", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report.html")
        html_content = template.render(report=report_data)

        # Write file atomically
        output_path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(output_path, html_content)

        return output_path

    def save_patch(
        self,
        healing: "HealingResult",
        target_id: str,
        run_id: str,
    ) -> Path | None:
        """Save healing patch to campaign directory.

        Args:
            healing: Healing result with text_fix
            target_id: Target identifier
            run_id: Campaign run ID

        Returns:
            Path to patch file, or None if dry run or no text_fix
        """
        if self._dry_run:
            return None

        if not healing.text_fix:
            return None

        campaign_dir = (
            self._storage_base / "targets" / target_id / CAMPAIGNS_DIR / run_id
        )
        campaign_dir.mkdir(parents=True, exist_ok=True)
        output_path = campaign_dir / PATCH_FILENAME

        # Write file atomically
        self._atomic_write(output_path, healing.text_fix.diff)

        return output_path

    def _atomic_write(self, path: Path, content: str) -> None:
        """Write file atomically using temp file + os.replace().

        Uses StorageService if available, otherwise implements inline.

        Args:
            path: Target file path
            content: Content to write
        """
        if self._storage:
            # Delegate to StorageService's atomic write
            self._storage._atomic_write(path, content)
        else:
            # Inline atomic write for standalone use
            tmp_path = path.with_suffix(path.suffix + ".tmp")
            try:
                tmp_path.write_text(content)
                os.replace(tmp_path, path)
            except Exception:
                if tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except Exception:
                        pass
                raise

    def _build_json_data(
        self,
        workflow_result: "WorkflowResult",
        target: str,
        healing: "HealingResult | None" = None,
        serix_version: str = "",
        depth: int = 5,
        mode: str = "adaptive",
    ) -> dict[str, Any]:
        """Build data dict for JSON export."""
        attacks_data = []
        for attack in workflow_result.attacks:
            attacks_data.append(
                {
                    "persona": attack.persona,
                    "goal": attack.goal,
                    "success": attack.success,
                    "confidence": attack.confidence,
                    "owasp_code": attack.owasp_code,
                    "winning_payload": attack.winning_payload,
                    "turns_taken": attack.turns_taken,
                    "conversation": attack.conversation,
                    "judge_reasoning": attack.judge_reasoning,
                }
            )

        return {
            "version": RESULTS_SCHEMA_VERSION,
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "passed": workflow_result.passed,
            "summary": {
                "total_attacks": workflow_result.total_attacks,
                "exploited": workflow_result.exploited,
                "defended": workflow_result.defended,
                "duration_seconds": workflow_result.duration_seconds,
                "exit_code": workflow_result.exit_code,
            },
            "attacks": attacks_data,
            "healing": self._build_healing_json(healing) if healing else None,
            "test_config": {
                "serix_version": serix_version,
                "depth": depth,
                "mode": mode,
            },
        }

    def _build_html_data(
        self,
        workflow_result: "WorkflowResult",
        target: str,
        healing: "HealingResult | None" = None,
        serix_version: str = "",
        depth: int = 5,
        mode: str = "adaptive",
    ) -> dict[str, Any]:
        """Build data dict for HTML template."""
        # Strategy breakdown
        strategy_breakdown: dict[str, dict[str, Any]] = {}
        for attack in workflow_result.attacks:
            if attack.persona not in strategy_breakdown:
                strategy_breakdown[attack.persona] = {"count": 0, "exploited": False}
            strategy_breakdown[attack.persona]["count"] += 1
            if attack.success:
                strategy_breakdown[attack.persona]["exploited"] = True

        # Build attacks data
        attacks_data = []
        for attack in workflow_result.attacks:
            attacks_data.append(
                {
                    "strategy": attack.persona,
                    "payload": attack.winning_payload or "",
                    "response": self._get_last_response(attack),
                    "success": attack.success,
                    "judge_reasoning": attack.judge_reasoning,
                    "owasp": {"code": attack.owasp_code} if attack.owasp_code else None,
                }
            )

        return {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "script_path": target,
            "goal": workflow_result.attacks[0].goal if workflow_result.attacks else "",
            "overall_status": "PASSED" if workflow_result.passed else "FAILED",
            "status_message": self._build_status_message(workflow_result),
            "total_attacks": workflow_result.total_attacks,
            "successful_attacks": workflow_result.exploited,
            "defended_attacks": workflow_result.defended,
            "exploit_rate": (
                workflow_result.exploited / workflow_result.total_attacks * 100
                if workflow_result.total_attacks > 0
                else 0
            ),
            "attacks": attacks_data,
            "strategy_breakdown": strategy_breakdown,
            "healing": self._build_healing_html_data(healing) if healing else None,
            "serix_version": serix_version,
            "test_duration_seconds": workflow_result.duration_seconds,
            "depth": depth,
            "mode": mode,
        }

    def _build_healing_json(self, healing: "HealingResult") -> dict[str, Any]:
        """Build healing data for JSON export."""
        return {
            "vulnerability_type": healing.vulnerability_type,
            "owasp_code": healing.owasp_code,
            "confidence": healing.confidence,
            "reasoning": healing.reasoning,
            "text_fix": (
                {
                    "diff": healing.text_fix.diff,
                    "explanation": healing.text_fix.explanation,
                }
                if healing.text_fix
                else None
            ),
            "tool_fixes": [
                {
                    "recommendation": f.recommendation,
                    "severity": f.severity,
                    "owasp_code": f.owasp_code,
                }
                for f in healing.tool_fixes
            ],
        }

    def _build_healing_html_data(self, healing: "HealingResult") -> dict[str, Any]:
        """Build healing data for HTML template."""
        return {
            "vulnerability_type": healing.vulnerability_type,
            "owasp_code": healing.owasp_code,
            "confidence": int(healing.confidence * 100),
            "reasoning": healing.reasoning,
            "has_text_fix": healing.text_fix is not None,
            "text_fix_diff": healing.text_fix.diff if healing.text_fix else "",
            "text_fix_explanation": (
                healing.text_fix.explanation if healing.text_fix else ""
            ),
            "patched_prompt": healing.text_fix.patched if healing.text_fix else "",
            "tool_fixes": [
                {
                    "recommendation": f.recommendation,
                    "severity": f.severity,
                    "owasp_code": f.owasp_code,
                }
                for f in healing.tool_fixes
            ],
        }

    def _get_last_response(self, attack: "AttackResult") -> str:
        """Extract last agent response from conversation."""
        if not attack.conversation:
            return ""
        for msg in reversed(attack.conversation):
            if msg.get("role") == "agent":
                return msg.get("content", "")
        return ""

    def _build_status_message(self, result: "WorkflowResult") -> str:
        """Build human-readable status message."""
        if result.passed:
            return f"Agent successfully defended against all {result.total_attacks} attacks"
        return f"Agent was compromised by {result.exploited} attack(s)"
