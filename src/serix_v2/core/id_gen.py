"""
Serix v2 - ID Generation

Law 6: Deterministic ID Law - IDs follow Spec 02 exactly.

Target IDs and Run IDs are generated here and NOWHERE ELSE.

Reference: Spec 02 (ID Generation Spec)
"""

import hashlib
import secrets
from datetime import datetime, timezone


def generate_target_id(
    locator: str,
    name: str | None = None,
    explicit_id: str | None = None,
) -> str:
    """
    Generate a target ID following the precedence rules.

    Precedence: explicit_id > name > auto-generated from locator

    Args:
        locator: The target path (e.g., "agent.py:my_agent" or "http://...")
        name: Optional stable alias (--name flag)
        explicit_id: Optional explicit ID (--target-id flag)

    Returns:
        Target ID in format "t_XXXXXXXX"

    Reference: Spec 02, Section 1.5
    """
    # Precedence 1: Explicit ID (use as-is, but validate format)
    if explicit_id:
        if not explicit_id.startswith("t_"):
            return f"t_{explicit_id}"
        return explicit_id

    # Precedence 2: Hash of name (stable alias)
    if name:
        hash_input = name
    # Precedence 3: Hash of locator (auto-generated)
    else:
        hash_input = locator

    # Generate 8-char hash
    hash_bytes = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    return f"t_{hash_bytes}"


def generate_run_id() -> str:
    """
    Generate a unique run ID for a campaign.

    Format: YYYYMMDD_HHMMSS_XXXX (timestamp + 4 random chars)

    Examples:
        - 20251225_143022_a1b2
        - 20251228_091500_f7c9

    Reference: Spec 1.3 (Run ID Generation)
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    random_suffix = secrets.token_hex(2)  # 4 hex chars
    return f"{timestamp}_{random_suffix}"


def generate_attack_id() -> str:
    """
    Generate a unique attack ID for storage.

    Format: UUID-style hex string (32 chars)

    Reference: Spec 1.4 (Attack ID stays random UUID)
    """
    return secrets.token_hex(16)
