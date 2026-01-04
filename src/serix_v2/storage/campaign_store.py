"""
Serix v2 - Campaign Store Implementation

Implements the CampaignStore protocol for persisting campaign results.

Storage paths:
- {base_dir}/targets/{target_id}/campaigns/{run_id}/results.json
- {base_dir}/targets/{target_id}/campaigns/{run_id}/patch.diff (if healing patches exist)
- {base_dir}/targets/{target_id}/campaigns/{run_id}/metadata.json (if config provided)
- {base_dir}/targets/{target_id}/campaigns/{run_id}/report.html (via save_report)

Reference: Phase 3A, Phase 10D, Spec 1.3, Spec 1.16
"""

from pathlib import Path
from typing import TYPE_CHECKING, Optional

from serix_v2.core.constants import APP_DIR
from serix_v2.core.contracts import AttackMode, CampaignResult, CampaignRunMetadata

if TYPE_CHECKING:
    from serix_v2.core.config import SerixSessionConfig


class FileCampaignStore:
    """
    File-based implementation of the CampaignStore protocol.

    Stores campaign results and artifacts at:
    {base_dir}/targets/{target_id}/campaigns/{run_id}/

    Files created:
    - results.json: Full campaign result (always)
    - patch.diff: Aggregated healing patches (if any successful attacks have patches)
    - metadata.json: Run configuration (if config provided)
    - report.html: HTML report copy (via save_report method)
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        """
        Initialize the campaign store.

        Args:
            base_dir: Base directory for storage. Defaults to ".serix"
        """
        self._base_dir = base_dir or Path(APP_DIR)

    def _get_result_path(self, target_id: str, run_id: str) -> Path:
        """Get the path to the campaign result file."""
        return (
            self._base_dir
            / "targets"
            / target_id
            / "campaigns"
            / run_id
            / "results.json"
        )

    def _get_campaign_dir(self, target_id: str, run_id: str) -> Path:
        """Get the campaign directory path."""
        return self._base_dir / "targets" / target_id / "campaigns" / run_id

    def save(
        self,
        result: CampaignResult,
        config: Optional["SerixSessionConfig"] = None,
    ) -> str:
        """
        Save campaign result and optional artifacts to disk.

        Creates:
        - results.json (campaign result - always)
        - patch.diff (aggregated healing patches, if any successful attacks)
        - metadata.json (run configuration, if config provided)

        Args:
            result: Campaign result to save
            config: Optional session config for metadata.json

        Returns:
            The run_id of the saved result.
        """
        path = self._get_result_path(result.target_id, result.run_id)
        path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Save results.json (UNCHANGED - same as before)
        path.write_text(result.model_dump_json(indent=2))

        # 2. Save patch.diff if any successful attacks have healing patches
        patch_content = self._extract_aggregated_patch(result)
        if patch_content:
            patch_path = path.parent / "patch.diff"
            patch_path.write_text(patch_content)

        # 3. Save metadata.json if config provided
        if config:
            metadata = self._build_run_metadata(result, config)
            metadata_path = path.parent / "metadata.json"
            metadata_path.write_text(metadata.model_dump_json(indent=2))

        return result.run_id

    def load(self, target_id: str, run_id: str) -> CampaignResult:
        """
        Load a specific campaign result.

        Raises:
            FileNotFoundError: If the result file doesn't exist.
        """
        path = self._get_result_path(target_id, run_id)

        if not path.exists():
            raise FileNotFoundError(f"Campaign result not found: {target_id}/{run_id}")

        return CampaignResult.model_validate_json(path.read_text())

    def save_report(
        self,
        target_id: str,
        run_id: str,
        report_path: Path,
    ) -> Path:
        """
        Copy HTML report to campaign directory.

        Args:
            target_id: Target identifier
            run_id: Campaign run identifier
            report_path: Path to the source HTML report file

        Returns:
            Path to the copied report in the campaign directory.

        Raises:
            FileNotFoundError: If source report doesn't exist.
        """
        if not report_path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        campaign_dir = self._get_campaign_dir(target_id, run_id)
        campaign_dir.mkdir(parents=True, exist_ok=True)

        dest_path = campaign_dir / "report.html"
        dest_path.write_text(report_path.read_text(encoding="utf-8"), encoding="utf-8")

        return dest_path

    def _extract_aggregated_patch(self, result: CampaignResult) -> Optional[str]:
        """
        Extract and aggregate all healing patches from successful attacks.

        Creates a single patch file with headers for each attack's diff.

        Args:
            result: Campaign result containing attack results

        Returns:
            Aggregated patch content, or None if no patches exist.
        """
        patches: list[str] = []

        for attack in result.attacks:
            if attack.success and attack.healing and attack.healing.patch:
                patch = attack.healing.patch
                owasp = attack.analysis.owasp_code if attack.analysis else "N/A"
                severity = attack.analysis.severity.value if attack.analysis else "N/A"
                confidence = attack.healing.confidence

                header = f"""# Attack: {attack.persona.value} - {attack.goal}
# OWASP: {owasp} | Severity: {severity} | Confidence: {confidence:.0%}
# ============================================================"""

                patches.append(f"{header}\n{patch.diff}")

        if not patches:
            return None

        file_header = f"""# ============================================================
# Serix Healing Patches
# Run: {result.run_id}
# Target: {result.target_id}
# Generated: {result.timestamp.isoformat()}
# ============================================================

"""
        return file_header + "\n\n".join(patches)

    def _build_run_metadata(
        self,
        result: CampaignResult,
        config: "SerixSessionConfig",
    ) -> CampaignRunMetadata:
        """
        Build run metadata from result and config.

        Args:
            result: Campaign result for identity fields
            config: Session config for test parameters

        Returns:
            CampaignRunMetadata ready for serialization.
        """
        return CampaignRunMetadata(
            run_id=result.run_id,
            target_id=result.target_id,
            serix_version=result.serix_version,
            timestamp=result.timestamp,
            mode=config.mode,
            depth=config.depth,
            goals=list(config.goals),
            scenarios=list(config.scenarios),
            attacker_model=config.attacker_model,
            judge_model=config.judge_model,
            critic_model=(
                config.critic_model if config.mode == AttackMode.ADAPTIVE else None
            ),
            patcher_model=(
                config.patcher_model if config.should_generate_patch() else None
            ),
            analyzer_model=config.analyzer_model,
            exhaustive=config.exhaustive,
            skip_regression=config.skip_regression,
            fuzz_enabled=config.should_run_fuzz_tests(),
        )
