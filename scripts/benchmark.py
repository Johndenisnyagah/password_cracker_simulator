"""
Measure how fast this simulator actually guesses, per algorithm.

Runs the real HashCracker engine (not a bare hashlib loop), so the numbers
include the Python overhead of generating candidates. Writes the results to
docs/benchmark-results.md and prints them.

    python scripts/benchmark.py            # full run, ~1 minute
    python scripts/benchmark.py --quick    # smoke run for CI, a few seconds
"""

from __future__ import annotations

import argparse
import asyncio
import platform
import sys
import time
from datetime import date
from pathlib import Path

import bcrypt

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from simulator import MAX_BRUTE_FORCE_SEARCH_SPACE, HashCracker

YEAR = 60 * 60 * 24 * 365


async def fast_rate(algorithm: str, max_length: int) -> float:
    """Guesses per second for an exhaustive lowercase brute force (no match)."""
    cracker = HashCracker(target_hash="0" * 64, algorithm=algorithm)
    start = time.perf_counter()
    async for _ in cracker.brute_force("lower", max_length):
        pass
    return cracker.total_attempts / (time.perf_counter() - start)


def bcrypt_check_seconds(cost: int, repeats: int) -> float:
    """Median wall-clock seconds for one checkpw at the given cost."""
    target = bcrypt.hashpw(b"benchmark", bcrypt.gensalt(rounds=cost))
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        bcrypt.checkpw(b"wrong-guess", target)
        times.append(time.perf_counter() - start)
    return sorted(times)[len(times) // 2]


def fmt_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:,.0f} ms"
    if seconds < 3600:
        return f"{seconds:,.0f} s"
    if seconds < YEAR:
        return f"{seconds / 86400:,.1f} days"
    return f"{seconds / YEAR:,.1f} years"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="small smoke run, no file written")
    args = parser.parse_args()

    max_length = 3 if args.quick else 5          # 18,278 or 12,356,630 candidates
    costs = (4,) if args.quick else (4, 10, 12)
    repeats = 3 if args.quick else 7
    space6 = MAX_BRUTE_FORCE_SEARCH_SPACE         # 26^6: every 6-char lowercase password

    rows = []
    for algorithm in ("md5", "sha1", "sha256"):
        rate = asyncio.run(fast_rate(algorithm, max_length))
        rows.append((algorithm, f"{rate:,.0f} guesses/s", fmt_duration(space6 / rate)))
    for cost in costs:
        per = bcrypt_check_seconds(cost, repeats)
        rows.append((f"bcrypt cost {cost}", f"{per * 1000:,.0f} ms/check", fmt_duration(space6 * per)))

    header = "| Algorithm | Measured speed | Time to try all 26^6 lowercase 6-char passwords |"
    lines = [header, "|---|---|---|"] + [f"| {a} | {b} | {c} |" for a, b, c in rows]
    table = "\n".join(lines)
    print(table)
    if args.quick:
        return

    machine = f"{platform.processor() or platform.machine()}, Python {platform.python_version()}"
    doc = f"""# Benchmark results

Measured on {date.today().isoformat()} with `python scripts/benchmark.py` ({machine}, one core).

{table}

## How to read this

- The fast hashes run through the simulator's own engine, which is single-threaded pure Python. Dedicated tools such as Hashcat on a GPU are many orders of magnitude faster, so these rows are a floor for an attacker, not a ceiling.
- bcrypt's cost is encoded in the hash (`$2b$12$...` is cost 12). Each +1 doubles the work. OWASP asks for a work factor of at least 10 and ranks bcrypt as a legacy choice behind Argon2id and scrypt.
- The last column is the full search time for one hash. The simulator refuses that work: brute force and mask runs stop at a 26^6 search-space cap, and bcrypt runs stop after 500 attempts or 30 s.
- A slow hash does not save a weak password. A dictionary attack against bcrypt still finds `qwerty` on the fourth guess; only the time per guess changes.
"""
    out = ROOT / "docs" / "benchmark-results.md"
    out.write_text(doc, encoding="utf-8")
    print(f"\nwrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
