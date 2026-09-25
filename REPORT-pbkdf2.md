# Karapace — Schema Registry basic-auth stores passwords with an insufficient PBKDF2 work factor (weak password hashing)

## Classification
- VRT: Broken Cryptography -> Weak Password Hashing / Insufficient Key-Derivation Work Factor (program-dependent; commonly P4/Low or informational)
- CWE: CWE-916 (Use of Password Hash With Insufficient Computational Effort); related CWE-326 (Inadequate Encryption Strength)
- Suggested severity: P4 (Low) hardening. Not remotely exploitable on its own — impact is realized only after the authfile is disclosed (backup, misconfigured mount, image layer, accidental commit), where it materially lowers offline-cracking cost. Typically accepted only when chained with an authfile-disclosure primitive.
- Affected asset: github.com/Aiven-Open/karapace — Schema Registry basic-auth password hashing (`src/karapace/core/auth.py`, `hash_password`), base commit `b960b4b`. Verified at runtime 2026-09-25.

## Summary
Karapace's Schema Registry basic-auth stores each user's password in the authfile as
`PBKDF2-HMAC-<algo>(password, salt, iterations)`. The iteration count is hardcoded to **5000**
(`hash_password`), which is one to two orders of magnitude below current guidance (OWASP 2023:
210,000 for PBKDF2-HMAC-SHA512, 600,000 for SHA256). PBKDF2's whole purpose is to make each guess
expensive; at 5000 iterations an attacker who obtains the authfile can try roughly 40x–120x more
candidate passwords per unit of cost than a compliant configuration would allow, so weak and
medium-strength passwords fall quickly to offline dictionary/brute-force attacks. `sha1` is also
still offered as a hashing algorithm. The count was not configurable and not stored, so operators
could not raise it without patching the code, and there was no migration path.

## Root cause (src/karapace/core/auth.py, commit b960b4b)
- `hash_password` (`auth.py:50`) — the PBKDF2 branch hardcodes the work factor at `auth.py:53`:

```python
def hash_password(algorithm: HashAlgorithm, salt: str, plaintext_password: str) -> str:
    if algorithm in [HashAlgorithm.SHA1, HashAlgorithm.SHA256, HashAlgorithm.SHA512]:
        return b64encode(
            hashlib.pbkdf2_hmac(algorithm.value, bytearray(plaintext_password, "UTF-8"), bytearray(salt, "UTF-8"), 5000)
        ).decode("ascii")
```

- The count is a literal (`5000`): not configurable, not stored next to the hash, and identical for
  `sha1`/`sha256`/`sha512`. `sha1` remains a selectable algorithm (`HashAlgorithm.SHA1`).
- `User.compare_password` (`auth.py:75-78`) re-derives with the same fixed `hash_password`, so
  verification is locked to 5000 as well:

```python
def compare_password(self, plaintext_password: str) -> bool:
    if self.algorithm is None or self.salt is None or self.password_hash is None:
        return False
    return compare_digest(self.password_hash, hash_password(self.algorithm, self.salt, plaintext_password))
```

- The authfile records only `algorithm`, `salt`, `password_hash` (`UserData`), so there is nowhere to
  express a per-user work factor and no way to migrate hashes forward.

## Steps to reproduce (runtime, verified)
Verified against the real `karapace.core.auth.hash_password`. The PoC recovers the EFFECTIVE default
iteration count by matching `hash_password()` output against a reference PBKDF2 computation, so it
needs nothing version-specific.

1. On the affected code, hash any password and recover the work factor:

```text
Effective DEFAULT iteration count produced by hash_password(): 5000
Verdict: WEAK (below password-storage guidance)
```

2. Demonstrate the cracking-cost gap directly. Same PBKDF2-HMAC-SHA256 primitive, same candidate
   list, single core on the test host — the only variable is the stored iteration count:

```text
iterations=   5000  ~298 guesses/sec/core   (affected default)
iterations= 210000  ~7   guesses/sec/core   (guidance baseline)
ratio 210000/5000 = 42x more work per guess
```

   At 5000 iterations an attacker with a leaked authfile grinds ~42x more candidate passwords per
   unit of cost than a compliant configuration would permit.

## Proof (real PoC output; see poc/karapace_pbkdf2_poc.py)
Affected code (`b960b4b`):

```text
Algorithm under test: PBKDF2-HMAC-sha256
Effective DEFAULT iteration count produced by hash_password(): 5000
Verdict: WEAK (below password-storage guidance)

Affected build: hash_password() has no configurable/self-describing iterations; default is fixed.

RESULT: VULNERABLE — default PBKDF2 work factor is insufficient (CWE-916).
```

Fixed code (branch `claude/tender-heisenberg-cooy3y`):

```text
Algorithm under test: PBKDF2-HMAC-sha256
Effective DEFAULT iteration count produced by hash_password(): 210000
Verdict: STRONG

Fixed build detected (LEGACY_PBKDF2_ITERATIONS=5000).
  Legacy 5000-iteration hash with NO iterations field still verifies: True
  Wrong password rejected: True

RESULT: HARDENED — default PBKDF2 work factor meets guidance; legacy hashes still verify.
```

## Impact
If the Schema Registry authfile is disclosed — via a backup, a world-readable mount, a container
image layer, log/config leakage, or an accidental commit — the 5000-iteration PBKDF2 hashes are far
cheaper to crack than modern guidance intends, so weak and medium-strength passwords are recovered
quickly with commodity offline tooling. Recovered credentials then grant whatever Schema Registry
access the ACLs assign to that user (read/register/delete schemas, change compatibility/mode). This
is a defense-in-depth / cryptographic-storage weakness: it is not exploitable directly over the
network and depends on a separate authfile-disclosure condition, hence the Low/hardening rating.

## Remediation
Make the PBKDF2 work factor strong by default, configurable, and self-describing so existing hashes
keep verifying:
- Default new hashes to a guidance-aligned count (210,000 for PBKDF2-HMAC-SHA512, the mkpasswd default
  algorithm), exposed via `karapace_mkpasswd -i/--iterations`.
- Store the count per user (`iterations` field); verification uses the stored count and falls back to
  5000 for records that predate the field, so pre-existing authfiles keep working with no forced
  re-hash.
- Consider dropping `sha1` as an offered algorithm and/or preferring `scrypt`.
- Note that HTTP Basic auth re-derives the hash on every authenticated request, so the count is a
  security/throughput trade-off; the self-describing format lets operators tune it safely.

A fix implementing exactly this is in commit `6886e54` on branch `claude/tender-heisenberg-cooy3y`
(`LEGACY_PBKDF2_ITERATIONS = 5000` fallback, `DEFAULT_PBKDF2_ITERATIONS = 210_000`, `iterations`
keyword on `hash_password`, `User.iterations` with legacy fallback, and `-i/--iterations` on
`karapace_mkpasswd`).

## Reproduce
Linux, Python 3.11+, a Karapace checkout. Install the pure-Python deps needed to import the auth
module, add a build-time version stub, then run the PoC:

```bash
pip install pydantic pydantic-settings watchfiles typing_extensions aiohttp orjson accept-types \
            dependency-injector opentelemetry-sdk fastapi prometheus-client \
            prometheus-fastapi-instrumentator async-timeout cachetools async-lru statsd
printf '__version__="0.0.0+poc"\n' > src/karapace/version.py   # normally generated by setuptools-scm

# Affected code -> RESULT: VULNERABLE (default 5000, exit 1)
git checkout b960b4b -- src/karapace/core/auth.py
PYTHONPATH=src python3 poc/karapace_pbkdf2_poc.py

# Fixed code -> RESULT: HARDENED (default 210000, legacy hashes still verify, exit 0)
git checkout claude/tender-heisenberg-cooy3y -- src/karapace/core/auth.py
PYTHONPATH=src python3 poc/karapace_pbkdf2_poc.py
```
