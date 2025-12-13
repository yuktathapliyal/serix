"""Recording and replay functionality for Serix."""

from __future__ import annotations

import json
from pathlib import Path

from serix.core.types import RecordingSession


def save_recording(session: RecordingSession, path: Path) -> None:
    """Save a recording session to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(session.model_dump(mode="json"), f, indent=2, default=str)


def load_recording(path: Path) -> RecordingSession:
    """Load a recording session from a JSON file."""
    with open(path) as f:
        data = json.load(f)
    return RecordingSession.model_validate(data)
