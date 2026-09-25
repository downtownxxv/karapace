"""
Copyright (c) 2025 Aiven Ltd
See LICENSE for details

Regression tests: JSON Schema compatibility normalization must not dereference external
``$ref`` targets. The legacy jsonschema resolver would otherwise fetch ``http(s)://`` URLs
(SSRF, incl. cloud metadata) and read ``file://`` paths (local file read) from attacker-
controlled schemas. Only same-document references (served from the resolver's store) are
allowed; anything requiring an outbound fetch is refused.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from jsonschema import Draft7Validator
from karapace.core.compatibility.jsonschema.utils import normalize_schema

import pytest
import threading


def test_in_document_ref_still_normalizes() -> None:
    """A same-document ``#/...`` reference resolves from the store and is inlined."""
    validator = Draft7Validator(
        {
            "type": "object",
            "properties": {"a": {"$ref": "#/definitions/a"}},
            "definitions": {"a": {"type": "string"}},
        }
    )

    normalized = normalize_schema(validator)

    assert normalized["properties"]["a"] == {"type": "string"}


def test_file_ref_is_refused_and_not_read(tmp_path) -> None:
    """A ``file://`` ``$ref`` must be refused; the local file must not be read."""
    secret = tmp_path / "secret.json"
    secret.write_text('{"leaked": "CANARY_should_not_be_read"}')
    validator = Draft7Validator({"type": "object", "properties": {"x": {"$ref": secret.as_uri()}}})

    with pytest.raises(Exception) as excinfo:  # noqa: PT011 - jsonschema wraps our error type
        normalize_schema(validator)

    assert "Refusing to dereference external JSON Schema reference" in str(excinfo.value)


def test_http_ref_is_refused_and_makes_no_request() -> None:
    """An ``http://`` ``$ref`` must be refused without any outbound request (SSRF)."""
    received: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            received.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args) -> None:  # silence
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        validator = Draft7Validator({"type": "object", "properties": {"x": {"$ref": f"http://127.0.0.1:{port}/ssrf"}}})

        with pytest.raises(Exception) as excinfo:  # noqa: PT011
            normalize_schema(validator)

        assert "Refusing to dereference external JSON Schema reference" in str(excinfo.value)
        assert received == [], "the registry must not have made an outbound request"
    finally:
        server.shutdown()
