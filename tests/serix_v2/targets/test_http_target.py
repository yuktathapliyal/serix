"""
Tests for HTTPTarget.

Uses respx for HTTP mocking to test:
- Basic HTTP functionality
- Nested JSON extraction
- Header merging
- Error handling
"""

import json
import tempfile
from pathlib import Path

import pytest
import respx
from httpx import Response

from serix_v2.targets import HTTPTarget


class TestBasicHTTPFunctionality:
    """Test basic HTTP request/response handling."""

    @respx.mock
    def test_http_target_basic(self) -> None:
        """Test basic HTTP POST and response extraction."""
        respx.post("http://localhost:8000/chat").mock(
            return_value=Response(200, json={"response": "Hello back!"})
        )

        target = HTTPTarget(url="http://localhost:8000/chat")
        result = target("Hello")
        assert result == "Hello back!"

    @respx.mock
    def test_custom_input_field(self) -> None:
        """Test custom input field name."""
        route = respx.post("http://localhost:8000/chat").mock(
            return_value=Response(200, json={"response": "OK"})
        )

        target = HTTPTarget(
            url="http://localhost:8000/chat",
            input_field="query",
        )
        target("Test message")

        # Verify the request used the custom input field
        request = route.calls[0].request
        body = json.loads(request.content)
        assert body == {"query": "Test message"}

    @respx.mock
    def test_custom_output_field(self) -> None:
        """Test custom output field name."""
        respx.post("http://localhost:8000/chat").mock(
            return_value=Response(200, json={"answer": "Custom output!"})
        )

        target = HTTPTarget(
            url="http://localhost:8000/chat",
            output_field="answer",
        )
        result = target("Test")
        assert result == "Custom output!"


class TestNestedJSONExtraction:
    """Test nested output_field extraction like 'data.message'."""

    @respx.mock
    def test_nested_json_extraction(self) -> None:
        """Test nested output_field like 'data.message'."""
        respx.post("http://api.example.com/v1/chat").mock(
            return_value=Response(200, json={"data": {"message": "Nested!"}})
        )

        target = HTTPTarget(
            url="http://api.example.com/v1/chat",
            output_field="data.message",
        )
        result = target("Test")
        assert result == "Nested!"

    @respx.mock
    def test_deeply_nested_extraction(self) -> None:
        """Test deeply nested paths."""
        respx.post("http://localhost:8000/api").mock(
            return_value=Response(
                200,
                json={
                    "result": {
                        "data": {
                            "content": "Deep value!",
                        }
                    }
                },
            )
        )

        target = HTTPTarget(
            url="http://localhost:8000/api",
            output_field="result.data.content",
        )
        result = target("Test")
        assert result == "Deep value!"

    @respx.mock
    def test_missing_output_field_error(self) -> None:
        """Test helpful error when output_field not found."""
        respx.post("http://localhost:8000/chat").mock(
            return_value=Response(200, json={"wrong_key": "value"})
        )

        target = HTTPTarget(
            url="http://localhost:8000/chat",
            output_field="response",
        )
        with pytest.raises(ValueError, match="Available keys"):
            target("Hello")

    @respx.mock
    def test_missing_nested_key_error(self) -> None:
        """Test error message shows available keys at the missing level."""
        respx.post("http://localhost:8000/chat").mock(
            return_value=Response(
                200,
                json={"data": {"other_field": "value"}},
            )
        )

        target = HTTPTarget(
            url="http://localhost:8000/chat",
            output_field="data.message",
        )
        with pytest.raises(ValueError, match="other_field"):
            target("Hello")


class TestHeaderMerging:
    """Test header merging from multiple sources."""

    @respx.mock
    def test_default_content_type_header(self) -> None:
        """Test that Content-Type is set by default."""
        route = respx.post("http://localhost:8000/chat").mock(
            return_value=Response(200, json={"response": "OK"})
        )

        target = HTTPTarget(url="http://localhost:8000/chat")
        target("Test")

        request = route.calls[0].request
        assert request.headers["content-type"] == "application/json"

    @respx.mock
    def test_custom_headers(self) -> None:
        """Test custom headers are included."""
        route = respx.post("http://localhost:8000/chat").mock(
            return_value=Response(200, json={"response": "OK"})
        )

        target = HTTPTarget(
            url="http://localhost:8000/chat",
            headers={"Authorization": "Bearer token123"},
        )
        target("Test")

        request = route.calls[0].request
        assert request.headers["authorization"] == "Bearer token123"

    def test_headers_file_json(self) -> None:
        """Test loading headers from a JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"X-Custom-Header": "from-file"}, f)
            headers_file = f.name

        try:
            target = HTTPTarget(
                url="http://localhost:8000/chat",
                headers_file=headers_file,
            )
            # Check headers were loaded
            assert "X-Custom-Header" in target._headers
            assert target._headers["X-Custom-Header"] == "from-file"
        finally:
            Path(headers_file).unlink()

    def test_headers_dict_overrides_file(self) -> None:
        """Test that headers dict takes precedence over file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"X-Header": "from-file"}, f)
            headers_file = f.name

        try:
            target = HTTPTarget(
                url="http://localhost:8000/chat",
                headers_file=headers_file,
                headers={"X-Header": "from-dict"},
            )
            assert target._headers["X-Header"] == "from-dict"
        finally:
            Path(headers_file).unlink()


class TestHeadersFileErrorHandling:
    """Test graceful error handling for headers_file issues."""

    def test_headers_file_not_found(self) -> None:
        """Test error when headers_file doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            HTTPTarget(
                url="http://localhost:8000/chat",
                headers_file="nonexistent.json",
            )

    def test_headers_file_invalid_json(self) -> None:
        """Test error when headers_file contains invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            headers_file = f.name

        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                HTTPTarget(
                    url="http://localhost:8000/chat",
                    headers_file=headers_file,
                )
        finally:
            Path(headers_file).unlink()

    def test_headers_file_not_dict(self) -> None:
        """Test error when headers_file contains non-dict JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["an", "array"], f)
            headers_file = f.name

        try:
            with pytest.raises(ValueError, match="JSON object"):
                HTTPTarget(
                    url="http://localhost:8000/chat",
                    headers_file=headers_file,
                )
        finally:
            Path(headers_file).unlink()


class TestIDGeneration:
    """Test target ID generation."""

    def test_id_starts_with_prefix(self) -> None:
        """Test that ID starts with 't_' prefix."""
        target = HTTPTarget(url="http://localhost:8000/chat")
        assert target.id.startswith("t_")

    def test_id_is_deterministic(self) -> None:
        """Test that same URL produces same ID."""
        target1 = HTTPTarget(url="http://localhost:8000/chat")
        target2 = HTTPTarget(url="http://localhost:8000/chat")
        assert target1.id == target2.id

    def test_different_urls_different_ids(self) -> None:
        """Test that different URLs produce different IDs."""
        target1 = HTTPTarget(url="http://localhost:8000/chat")
        target2 = HTTPTarget(url="http://localhost:8000/api")
        assert target1.id != target2.id

    def test_name_overrides_url_for_id(self) -> None:
        """Test that --name flag overrides URL for ID."""
        target_no_name = HTTPTarget(url="http://localhost:8000/chat")
        target_with_name = HTTPTarget(
            url="http://localhost:8000/chat",
            name="my-api",
        )
        assert target_no_name.id != target_with_name.id

    def test_explicit_id_overrides_all(self) -> None:
        """Test that --target-id flag overrides everything."""
        target = HTTPTarget(
            url="http://localhost:8000/chat",
            name="some-name",
            explicit_id="custom-id",
        )
        assert target.id == "t_custom-id"


class TestLocatorProperty:
    """Test the locator property."""

    def test_locator_returns_url(self) -> None:
        """Test that locator property returns the URL."""
        url = "http://localhost:8000/chat"
        target = HTTPTarget(url=url)
        assert target.locator == url


class TestContextManager:
    """Test context manager support."""

    def test_context_manager(self) -> None:
        """Test using HTTPTarget as context manager."""
        with HTTPTarget(url="http://localhost:8000/chat") as target:
            assert target.locator == "http://localhost:8000/chat"
        # Client should be closed after exiting


class TestRepr:
    """Test string representation."""

    def test_repr_includes_useful_info(self) -> None:
        """Test that repr includes useful info."""
        target = HTTPTarget(
            url="http://localhost:8000/chat",
            input_field="query",
            output_field="answer",
        )
        repr_str = repr(target)
        assert "HTTPTarget" in repr_str
        assert "http://localhost:8000/chat" in repr_str
        assert "query" in repr_str
        assert "answer" in repr_str
