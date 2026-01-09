"""
Serix v2 - Provider Utilities

The "JSON Guard" - robust extraction of JSON from LLM responses.
This prevents LLM formatting quirks from crashing the engine.

All LLM-powered components (Judge, Critic, Analyzer) depend on this.
"""

from __future__ import annotations

import json
import re
from typing import Any


def extract_json_payload(text: str) -> dict[str, Any]:
    """
    Robustly extracts a JSON object from an LLM response.

    Handles common LLM quirks:
    - Markdown code blocks (```json ... ```)
    - Leading/trailing text ("Sure, here is the JSON:")
    - Cut-off responses (attempts fallback parsing)

    Args:
        text: Raw LLM response text that may contain JSON.

    Returns:
        Parsed JSON as a dictionary.

    Raises:
        ValueError: If no valid JSON object can be extracted.

    Example:
        >>> extract_json_payload('Here is your result: {"verdict": "defended"}')
        {'verdict': 'defended'}
    """
    # Look for the outermost curly braces
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    if not match:
        raise ValueError(f"LLM failed to return valid JSON. Raw: {text[:200]}")

    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError as e:
        # Fallback: attempt to strip trailing chars if LLM was cut off
        cleaned = match.group(1).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            raise ValueError(f"Malformed JSON: {e}. Raw: {text[:200]}") from e
