# Karapace — Schema Registry ACL grants access to sibling subjects the operator never authorized (broken access control via unanchored authorization regex)

## Classification
- VRT: Broken Access Control -> Insufficient / Missing Authorization (privilege escalation)
- CWE: CWE-863 (Incorrect Authorization) via CWE-777 (Regular Expression without Anchors)
- Suggested severity: P3 (Medium) — rises to P2 (High) when a granted pattern is a prefix of a more-sensitive sibling subject (a common outcome of shared topic/environment/team subject prefixes)
- Affected asset: github.com/Aiven-Open/karapace — Schema Registry basic-auth authorizer (`src/karapace/core/auth.py`), base commit `b960b4b`. Verified at runtime 2026-09-25.

## Summary
Karapace's Schema Registry authorizes every subject/config/mode operation through a single choke point,
`ACLAuthorizer.check_authorization(user, operation, "Subject:<name>")`, which matches the accessed resource
against the operator-supplied ACL `resource` regex. That match uses `re.Pattern.match()`, which is anchored
only at the **start** of the string. As a result every ACL pattern behaves as a prefix pattern regardless of
operator intent: a permission written for the literal resource `Subject:orders` also authorizes
`Subject:orders-secret`, `Subject:orders-pii`, `Subject:ordersX`, and any other subject sharing that prefix.
Karapace documents `resource` as a "regular expression" whose wildcards are written explicitly (e.g.
`Subject:general.*`), so an operator who writes a literal or otherwise end-bounded pattern reasonably expects
an exact grant — but the engine silently grants strictly more than the string they wrote. Because `Write`
implies `Read` and write patterns are matched identically, this over-grant covers both reading and mutating
(register / delete schema versions of) the sibling subjects. Exploitable by any authenticated user holding
such a grant; no elevated role is required.

## Root cause (src/karapace/core/auth.py, commit b960b4b)
- `ACLAuthorizer._check_resources` (`auth.py:166`) — the resource test:
  - `auth.py:168` — `if aclentry.resource.match(resource) is not None:` &nbsp; `re.Pattern.match()` anchors only at
    the start, so `resource` merely has to *begin* with a string the pattern accepts; the tail is unchecked.
- `HTTPAuthorizer._load_authfile` (`auth.py:268`) — the pattern is compiled verbatim from the authfile with
  `re.compile(entry["resource"])`, with no start/end anchoring added.
- `ACLAuthorizer._check_operation` (`auth.py:172-176`) — `Write` implies `Read`, so a `Write` grant on a
  prefix leaks write access to sibling subjects too (register/delete schema versions).
- Every subject route funnels through this one check, e.g. `src/karapace/api/routers/subjects.py:62, 86, 112,
  136, 153, 173, 196, 212` — `authorizer.check_authorization(user, Operation.Read|Write, f"Subject:{subject}")`;
  the same pattern guards `config` (`routers/config.py`) and `mode` (`routers/mode.py`). The subject taken from
  the request path is interpolated directly into the resource string, so the unanchored match decides access
  for arbitrary attacker-chosen subject names.
- Documented intent — `README.rst` describes `resource` as "A regular expression used to match against
  accessed resource" and its examples spell wildcards explicitly (`.*`, `Subject:general.*`), implying a
  whole-string match; nothing tells operators that a literal grant silently extends to every prefixed sibling.

## Steps to reproduce (runtime, verified)
Verified against the real `karapace.core.auth.ACLAuthorizer` — the exact object and method every subject/
config/mode route calls to make its access decision. (An authorization bug is decided entirely by this
authorizer; the HTTP routers add no further subject-scoping, they only forward `f"Subject:{subject}"` to it.)

Preconditions: an operator grants an ordinary user `alice` read on the single subject she needs — a natural,
literal ACL entry `{"username":"alice","operation":"Read","resource":"Subject:orders"}` — while a separate,
sensitive subject `orders-secret` exists in the same tenant.

1. Build the authorizer with that grant and issue the exact call the router makes for the intended subject:

    check_authorization(alice, Read, "Subject:orders")            -> True    (intended)

2. Issue the same call for a DIFFERENT subject that merely shares the prefix:

    check_authorization(alice, Read, "Subject:orders-secret")     -> True    (BYPASS — never granted)
    check_authorization(alice, Read, "Subject:orders-pii")        -> True    (BYPASS)
    check_authorization(alice, Read, "Subject:ordersX")           -> True    (BYPASS)

   At the HTTP layer this is: `GET /subjects/orders-secret/versions/latest` with alice's Basic credentials
   returns `200` and the schema body, instead of the `404` an unauthorized caller must receive.

## Proof (authorizer ground truth; see poc/karapace_acl_authz_poc.py)

Vulnerable code (`b960b4b`):

    Granted ACL: user=alice op=Read resource_pattern='Subject:orders'
      re.match('Subject:orders', 'Subject:orders-secret')     -> <re.Match object; span=(0, 14) ...>
      re.fullmatch('Subject:orders', 'Subject:orders-secret')  -> None
    check_authorization(alice, Read, <resource>):
      [OK  ] resource='Subject:orders'           authorized=True  (expected True)
      [LEAK] resource='Subject:orders-secret'    authorized=True  (expected False)
      [LEAK] resource='Subject:orders-pii'       authorized=True  (expected False)
      [LEAK] resource='Subject:ordersX'          authorized=True  (expected False)
    RESULT: VULNERABLE

`alice`, granted only `Subject:orders`, is authorized to read `Subject:orders-secret` (and every other
prefixed subject) — a subject the operator never granted her. Because `Write` implies `Read` and uses the same
matcher, the identical flaw lets a `Write` grant on a prefix register or delete schema versions of the sibling
subjects. The same over-match applies to `Config:` and `Mode:` resources routed through the same authorizer.

## Impact
Any authenticated Schema Registry user can read — and, with a `Write` grant, mutate (register/soft- or
hard-delete schema versions of) — every subject whose name shares a prefix with a resource pattern they were
legitimately granted, with no involvement from whoever owns those sibling subjects. Schema definitions and
subject compatibility are exactly the data ACLs are meant to compartmentalize (e.g. per team, per environment,
per data-sensitivity), and shared prefixes are the norm (`orders`, `orders-dlq`, `orders-pii`;
`teamA.<x>`; `prod-<x>`). The flaw needs no elevated role — it is reachable by the lowest privilege that holds
any ACL grant — and it silently contradicts the least-privilege intent of every literal or end-bounded ACL
entry an operator writes.

## Remediation
In `ACLAuthorizer._check_resources` match the whole resource string with `re.Pattern.fullmatch()` instead of
`re.Pattern.match()` (equivalently, compile patterns anchored with `\A...\Z` in `_load_authfile`). Wildcards
then remain explicit and continue to work (`Subject:orders.*`), while a literal grant means exactly that
resource. Document in `README.rst` that `resource` patterns are fully anchored. Every ACL pattern shipped in
the project's own tests and fixtures already uses `.*` or exact strings, so documented configurations are
unaffected.

A fix implementing exactly this (plus regression tests for the anchoring, the `.*`-wildcard behaviour, and the
existing integration fixture) is available in commit `6886e54` on branch `claude/tender-heisenberg-cooy3y`:

    -            if aclentry.resource.match(resource) is not None:
    +            if aclentry.resource.fullmatch(resource) is not None:

## Reproduce
Linux, Python 3.11+, a Karapace checkout. Install the pure-Python deps needed to import the auth module, add a
build-time version stub, then run the PoC (it drives the real `ACLAuthorizer` and prints the decision matrix,
exiting non-zero when a leak is detected):

    pip install pydantic pydantic-settings watchfiles typing_extensions aiohttp orjson accept-types \
                dependency-injector opentelemetry-sdk fastapi prometheus-client \
                prometheus-fastapi-instrumentator async-timeout cachetools async-lru statsd
    printf '__version__="0.0.0+poc"\n' > src/karapace/version.py   # normally generated by setuptools-scm

    # Affected code -> RESULT: VULNERABLE (exit 1)
    git checkout b960b4b -- src/karapace/core/auth.py
    PYTHONPATH=src python3 poc/karapace_acl_authz_poc.py

    # Fixed code -> RESULT: SAFE (exit 0)
    git checkout claude/tender-heisenberg-cooy3y -- src/karapace/core/auth.py
    PYTHONPATH=src python3 poc/karapace_acl_authz_poc.py
