"""
Serix v2 - HTTP Target

Calls HTTP endpoints with configurable JSON field mapping.

Law 3: Implements the Target protocol from core/protocols.py
Law 6: Uses generate_target_id() from core/id_gen.py for ID generation
Spec 1.14: Supports input_field, output_field, headers, headers_file
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from serix_v2.core.id_gen import generate_target_id


class HTTPTarget:
    """Calls an HTTP endpoint with configurable JSON fields.

    Supports:
    - Custom input field name (where to put the attack payload)
    - Custom output field name (where to extract the response)
    - Nested output paths like "data.message"
    - Custom headers from dict or JSON file

    The Target protocol requires:
    - id: str property
    - locator: str property
    - __call__(message: str) -> str
    """

    def __init__(
        self,
        url: str,
        input_field: str = "message",
        output_field: str = "response",
        headers: dict[str, str] | None = None,
        headers_file: str | None = None,  # JSON only
        name: str | None = None,  # --name flag (stable alias)
        explicit_id: str | None = None,  # --target-id flag (override)
        timeout: float = 30.0,
    ) -> None:
        """Initialize the HTTP target.

        Args:
            url: The HTTP endpoint URL to call.
            input_field: JSON key for the attack payload in the request.
            output_field: JSON key/path for extracting response (supports "a.b.c").
            headers: Custom headers to include in requests.
            headers_file: Path to a JSON file containing headers.
            name: Optional stable alias for ID generation (--name flag).
            explicit_id: Optional explicit ID override (--target-id flag).
            timeout: Request timeout in seconds.
        """
        self._url = url
        self._input_field = input_field
        self._output_field = output_field
        self._headers = self._merge_headers(headers, headers_file)
        self._client = httpx.Client(timeout=timeout)

        # Law 6: Generate ID using core logic with full precedence
        # explicit_id > name > auto-hash from locator
        self._id = generate_target_id(
            locator=url,
            name=name,
            explicit_id=explicit_id,
        )

    def _merge_headers(
        self,
        headers: dict[str, str] | None,
        headers_file: str | None,
    ) -> dict[str, str]:
        """Merge headers from multiple sources.

        Priority: headers dict > headers_file > defaults

        Args:
            headers: Headers dict to include.
            headers_file: Path to JSON file with headers.

        Returns:
            Merged headers dict.

        Raises:
            ValueError: If headers_file is invalid (not found, not JSON, not dict).
        """
        result: dict[str, str] = {"Content-Type": "application/json"}

        if headers_file:
            try:
                with open(headers_file) as f:
                    file_headers = json.load(f)
                    if not isinstance(file_headers, dict):
                        raise ValueError(
                            f"headers_file must contain a JSON object, "
                            f"got {type(file_headers).__name__}"
                        )
                    result.update(file_headers)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in headers_file '{headers_file}': {e}")
            except FileNotFoundError:
                raise ValueError(f"headers_file not found: '{headers_file}'")

        if headers:
            result.update(headers)

        return result

    def _extract_nested(self, data: dict[str, Any], path: str) -> str:
        """Extract value from nested path like 'data.message'.

        Args:
            data: The JSON response dict.
            path: Dot-separated path to the value.

        Returns:
            The extracted value as a string.

        Raises:
            ValueError: If the path is not found (with helpful error).
        """
        original_data = data
        current = data

        for key in path.split("."):
            if not isinstance(current, dict):
                available = (
                    list(original_data.keys())
                    if isinstance(original_data, dict)
                    else []
                )
                raise ValueError(
                    f"output_field '{path}' traversed into non-dict. "
                    f"Top-level keys: {available}"
                )
            if key not in current:
                available = list(current.keys())
                raise ValueError(
                    f"output_field '{path}' not found in response. "
                    f"Available keys at this level: {available}"
                )
            current = current[key]

        return str(current)

    @property
    def id(self) -> str:
        """Unique identifier for this target."""
        return self._id

    @property
    def locator(self) -> str:
        """Original locator string (the URL)."""
        return self._url

    def __call__(self, message: str) -> str:
        """Send a message to the HTTP endpoint and get a response.

        Args:
            message: The attack payload to send.

        Returns:
            The target's response as a string.

        Raises:
            httpx.HTTPStatusError: If the response has an error status.
            ValueError: If the output_field path is not found.
        """
        payload = {self._input_field: message}
        response = self._client.post(
            self._url,
            json=payload,
            headers=self._headers,
        )
        response.raise_for_status()
        data = response.json()
        return self._extract_nested(data, self._output_field)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "HTTPTarget":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"HTTPTarget(url={self._url!r}, "
            f"input_field={self._input_field!r}, "
            f"output_field={self._output_field!r}, "
            f"id={self._id!r})"
        )
