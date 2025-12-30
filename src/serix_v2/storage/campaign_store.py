"""
Serix v2 - Campaign Store Implementation

Implements the CampaignStore protocol for persisting campaign results.

Storage path: {base_dir}/targets/{target_id}/campaigns/{run_id}/results.json

Reference: Phase 3A, Spec 1.16
"""

from pathlib import Path

from serix_v2.core.constants import APP_DIR
from serix_v2.core.contracts import CampaignResult


class FileCampaignStore:
    """
    File-based implementation of the CampaignStore protocol.

    Stores campaign results as JSON files at:
    {base_dir}/targets/{target_id}/campaigns/{run_id}/results.json
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

    def save(self, result: CampaignResult) -> str:
        """
        Save campaign result to disk.

        Creates directories if they don't exist.

        Returns:
            The run_id of the saved result.
        """
        path = self._get_result_path(result.target_id, result.run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(result.model_dump_json(indent=2))
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
