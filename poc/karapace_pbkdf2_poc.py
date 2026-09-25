#!/usr/bin/env python3
"""
PoC: Karapace Schema Registry basic-auth password hashing uses an insufficient
PBKDF2 work factor (CWE-916).

The Schema Registry authfile stores each password as
PBKDF2-HMAC-<algo>(password, salt, iterations). On the affected code the iteration
count is hardcoded to 5000 (`hash_password`, src/karapace/core/auth.py), far below
current guidance (OWASP: 210k for SHA512, 600k for SHA256). A low work factor makes
offline cracking of a leaked authfile dramatically cheaper.

This PoC calls only the 3-argument hash_password(algorithm, salt, password), which
exists on both the affected and fixed code, and recovers the EFFECTIVE default
iteration count by matching the output against a reference PBKDF2 computation. It
therefore reports WEAK on the affected code and STRONG on the fixed code without
importing anything version-specific.

It then checks (only where the fixed, self-describing API exists) that a legacy
5000-iteration hash stored WITHOUT an iterations field still verifies, i.e. the
hardening is backwards compatible.

Usage:
    PYTHONPATH=src python3 poc/karapace_pbkdf2_poc.py
"""

from __future__ import annotations

import base64
import hashlib
import sys
import types

_stats = types.ModuleType("karapace.core.stats")
_stats.StatsClient = type("StatsClient", (), {})
sys.modules.setdefault("karapace.core.stats", _stats)

from karapace.core.auth import HashAlgorithm, hash_password  # noqa: E402

WEAK_THRESHOLD = 100_000  # anything below this is inadequate for password storage
CANDIDATES = (5_000, 100_000, 210_000, 600_000)


def reference_pbkdf2(algo: str, password: str, salt: str, iterations: int) -> str:
    return base64.b64encode(hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), iterations)).decode("ascii")


def recover_default_iterations(algo: str, password: str, salt: str) -> int | None:
    observed = hash_password(HashAlgorithm(algo), salt, password)  # 3-arg form: affected AND fixed
    for n in CANDIDATES:
        if observed == reference_pbkdf2(algo, password, salt, n):
            return n
    return None


def main() -> int:
    algo, password, salt = "sha256", "password", "salt"
    effective = recover_default_iterations(algo, password, salt)

    print(f"Algorithm under test: PBKDF2-HMAC-{algo}")
    print(f"Effective DEFAULT iteration count produced by hash_password(): {effective}")
    verdict_weak = effective is not None and effective < WEAK_THRESHOLD
    print(f"Verdict: {'WEAK (below password-storage guidance)' if verdict_weak else 'STRONG'}")
    print()

    # Backwards-compatibility of the fix (only meaningful where the new API exists).
    try:
        from karapace.core.auth import LEGACY_PBKDF2_ITERATIONS, User

        legacy_hash = hash_password(
            HashAlgorithm.SHA512, "s", "opensesame", iterations=LEGACY_PBKDF2_ITERATIONS
        )
        # Stored WITHOUT an iterations field, exactly like a pre-existing authfile entry.
        legacy_user = User(username="x", algorithm=HashAlgorithm.SHA512, salt="s", password_hash=legacy_hash, iterations=None)
        print(f"Fixed build detected (LEGACY_PBKDF2_ITERATIONS={LEGACY_PBKDF2_ITERATIONS}).")
        print(f"  Legacy 5000-iteration hash with NO iterations field still verifies: {legacy_user.compare_password('opensesame')}")
        print(f"  Wrong password rejected: {legacy_user.compare_password('nope') is False}")
    except ImportError:
        print("Affected build: hash_password() has no configurable/self-describing iterations; default is fixed.")

    print()
    if verdict_weak:
        print("RESULT: VULNERABLE — default PBKDF2 work factor is insufficient (CWE-916).")
        return 1
    print("RESULT: HARDENED — default PBKDF2 work factor meets guidance; legacy hashes still verify.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
