"""
Password-storage auditor.

Paste a hash and this module says whether the way it was produced meets the
OWASP Password Storage Cheat Sheet's minimums - the defensive counterpart to
the cracker. It identifies the algorithm from the hash's own structure and
grades its parameters; it never needs the plaintext.

References:
    OWASP Password Storage Cheat Sheet (algorithm ranking and minimum params).

Verdict grades:
    "strong"   - a modern KDF at or above the recommended parameters.
    "weak"     - a password KDF, but below the recommended parameters.
    "unsuitable" - a fast general-purpose hash (MD5/SHA-*): not for passwords.
    "unknown"  - the hash does not match a recognised format.
"""

from __future__ import annotations

import re

# OWASP minimums (Password Storage Cheat Sheet).
BCRYPT_MIN_COST = 10
ARGON2_MIN_MEMORY_KIB = 19456   # 19 MiB
ARGON2_MIN_TIME_COST = 2
PBKDF2_SHA256_MIN_ITERATIONS = 600_000

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BCRYPT_RE = re.compile(r"^\$2[abxy]?\$(\d{2})\$[./A-Za-z0-9]{53}$")
_ARGON2_RE = re.compile(
    r"^\$argon2(?P<variant>id|i|d)\$v=\d+\$m=(?P<m>\d+),t=(?P<t>\d+),p=(?P<p>\d+)\$"
)
_PBKDF2_RE = re.compile(r"^pbkdf2_sha256\$(?P<iters>\d+)\$[^$]+\$[^$]+$")

# Fast hashes keyed by hex digest length.
_FAST_BY_LENGTH = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}


def _result(algorithm: str, verdict: str, summary: str,
            recommendation: str, details: dict | None = None) -> dict:
    return {
        "algorithm": algorithm,
        "verdict": verdict,
        "summary": summary,
        "recommendation": recommendation,
        "details": details or {},
    }


def audit_hash(target_hash: str) -> dict:
    """Grade how a pasted password hash was stored against OWASP minimums."""
    h = (target_hash or "").strip()
    if not h:
        return _result("none", "unknown", "No hash provided.",
                       "Paste a password hash to audit it.")

    if (m := _BCRYPT_RE.match(h)):
        cost = int(m.group(1))
        ok = cost >= BCRYPT_MIN_COST
        return _result(
            "bcrypt",
            "strong" if ok else "weak",
            f"bcrypt at cost {cost}.",
            (f"Meets the OWASP minimum work factor of {BCRYPT_MIN_COST}. "
             "OWASP now ranks Argon2id and scrypt ahead of bcrypt for new systems.")
            if ok else
            f"Below the OWASP minimum work factor of {BCRYPT_MIN_COST}; raise the cost.",
            {"cost": cost, "min_cost": BCRYPT_MIN_COST},
        )

    if (m := _ARGON2_RE.match(h)):
        variant, mem, t, p = (m.group("variant"), int(m.group("m")),
                              int(m.group("t")), int(m.group("p")))
        ok = variant == "id" and mem >= ARGON2_MIN_MEMORY_KIB and t >= ARGON2_MIN_TIME_COST
        notes = []
        if variant != "id":
            notes.append(f"use Argon2id, not Argon2{variant}")
        if mem < ARGON2_MIN_MEMORY_KIB:
            notes.append(f"raise memory to >= {ARGON2_MIN_MEMORY_KIB} KiB (is {mem})")
        if t < ARGON2_MIN_TIME_COST:
            notes.append(f"raise time cost to >= {ARGON2_MIN_TIME_COST} (is {t})")
        return _result(
            f"argon2{variant}",
            "strong" if ok else "weak",
            f"Argon2{variant}, m={mem} KiB, t={t}, p={p}.",
            "Meets OWASP's Argon2id minimum (19 MiB, t=2, p=1)." if ok
            else "Below OWASP's Argon2id minimum: " + "; ".join(notes) + ".",
            {"variant": variant, "memory_kib": mem, "time_cost": t, "parallelism": p},
        )

    if (m := _PBKDF2_RE.match(h)):
        iters = int(m.group("iters"))
        ok = iters >= PBKDF2_SHA256_MIN_ITERATIONS
        return _result(
            "pbkdf2_sha256",
            "strong" if ok else "weak",
            f"PBKDF2-HMAC-SHA256 at {iters:,} iterations.",
            (f"Meets the OWASP minimum of {PBKDF2_SHA256_MIN_ITERATIONS:,} iterations.")
            if ok else
            f"Below the OWASP minimum of {PBKDF2_SHA256_MIN_ITERATIONS:,} iterations.",
            {"iterations": iters, "min_iterations": PBKDF2_SHA256_MIN_ITERATIONS},
        )

    if _HEX_RE.match(h) and len(h) in _FAST_BY_LENGTH:
        name = _FAST_BY_LENGTH[len(h)]
        return _result(
            name.lower().replace("-", ""),
            "unsuitable",
            f"Looks like a bare {name} digest.",
            (f"{name} is a fast general-purpose hash, not a password KDF: an "
             "attacker can try billions of guesses per second. Store passwords "
             "with Argon2id (first choice), scrypt, or bcrypt instead."),
            {"digest_length": len(h)},
        )

    return _result(
        "unknown", "unknown", "Unrecognised hash format.",
        "Could not match bcrypt, Argon2, PBKDF2, or a hex MD5/SHA digest.",
    )
