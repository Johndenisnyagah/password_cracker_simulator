"""
Core simulation engine for the Password Cracker Simulator.

This module contains HashCracker, which models three real-world password attack
strategies against a target hash:

    * brute_force   - iterate every candidate over a charset up to max_length
    * dictionary    - try entries from a wordlist
    * mask          - Hashcat-style mask (e.g. "?l?l?l?d?d") to constrain the search

Supported hash algorithms: md5, sha1, sha256, bcrypt.

Educational use only. The simulator hashes its own guesses locally and compares
them to the user-supplied target hash - it never sends data anywhere.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import math
import re
import string
import time
from collections.abc import AsyncIterator, Iterable
from pathlib import Path

try:
    import bcrypt  # type: ignore
    _BCRYPT_AVAILABLE = True
except ImportError:  # pragma: no cover - bcrypt is in requirements.txt
    _BCRYPT_AVAILABLE = False


# --- Constants & configuration ----------------------------------------------

CHARSETS: dict[str, str] = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "alphanumeric": string.ascii_letters + string.digits,
    "all": string.ascii_letters + string.digits + string.punctuation,
}

MASK_TOKENS: dict[str, str] = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": string.punctuation,
    "a": string.ascii_letters + string.digits + string.punctuation,
}

SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "bcrypt")

# Hard safety cap on brute-force search space. This engine is pure Python and
# measures ~1M guesses/sec on one core (docs/benchmark-results.md), so
# ~308M candidates is roughly five minutes of work - large enough to demo,
# small enough that the server cannot be tied up indefinitely.
MAX_BRUTE_FORCE_SEARCH_SPACE = 26 ** 6  # 308,915,776

# Bcrypt is intentionally slow. A brute-force attack is essentially intractable,
# so every bcrypt run (brute force, dictionary or mask) stops after a token
# sample: whichever of these two limits is reached first.
MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS = 500
MAX_BCRYPT_SECONDS = 30.0

# bcrypt runs emit a progress event this often (each check takes 1-300 ms).
BCRYPT_PROGRESS_INTERVAL = 10

# How often the running generator emits a progress event back to the websocket.
PROGRESS_INTERVAL = 50_000

# How often we let the asyncio event loop run other tasks during a CPU-bound loop.
YIELD_INTERVAL = 10_000


# --- Custom exceptions ------------------------------------------------------

class CrackerError(Exception):
    """Base class for all simulator errors surfaced to the user."""


class SearchSpaceTooLargeError(CrackerError):
    """Raised when the requested brute-force space exceeds the safety cap."""


class InvalidMaskError(CrackerError):
    """Raised when a mask string contains an unknown token or no charset chars."""


# --- Helpers ----------------------------------------------------------------

def _hashlib_digest(candidate: str, algorithm: str) -> str:
    """Hash `candidate` with one of the supported hashlib algorithms."""
    h = hashlib.new(algorithm)
    h.update(candidate.encode("utf-8"))
    return h.hexdigest()


_BCRYPT_PREFIX = re.compile(r"^\$2[abxy]?\$(\d{2})\$")


def bcrypt_cost(target_hash: str) -> int | None:
    """Return the cost (log2 rounds) encoded in a bcrypt hash, e.g. 12 for $2b$12$..."""
    match = _BCRYPT_PREFIX.match(target_hash.strip())
    return int(match.group(1)) if match else None


def human_duration(seconds: float) -> str:
    """Render a duration in the largest sensible unit (s, hours, days, years)."""
    if seconds < 3600:
        return f"{seconds:,.0f} seconds"
    if seconds < 86400:
        return f"{seconds / 3600:,.1f} hours"
    if seconds < 60 * 60 * 24 * 365:
        return f"{seconds / 86400:,.1f} days"
    return f"{seconds / (60 * 60 * 24 * 365):,.1f} years"


def expand_mask(mask: str) -> list[str]:
    """
    Expand a Hashcat-style mask into the per-position charset list.

    Tokens: ?l (lower), ?u (upper), ?d (digits), ?s (special), ?a (all).
    Any non-token char is treated as a literal (single-char position).
    """
    if not mask:
        raise InvalidMaskError("Mask is empty")

    positions: list[str] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?":
            if i + 1 >= len(mask):
                raise InvalidMaskError("Mask ends with a dangling '?'")
            token = mask[i + 1]
            if token not in MASK_TOKENS:
                raise InvalidMaskError(f"Unknown mask token '?{token}'")
            positions.append(MASK_TOKENS[token])
            i += 2
        else:
            positions.append(ch)
            i += 1

    if not positions:
        raise InvalidMaskError("Mask produced no positions")
    return positions


# --- Main class -------------------------------------------------------------

class HashCracker:
    """
    Asynchronous hash-cracking engine.

    Instantiate with the target hash and algorithm, then await one of
    brute_force, dictionary, or mask as an async generator that streams progress
    updates suitable for forwarding over a WebSocket.
    """

    def __init__(self, target_hash: str, algorithm: str) -> None:
        algorithm = algorithm.lower()
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise CrackerError(f"Unsupported algorithm: {algorithm}")
        if algorithm == "bcrypt" and not _BCRYPT_AVAILABLE:
            raise CrackerError("bcrypt is not installed on the server")

        self.target_hash = target_hash.strip()
        self.algorithm = algorithm
        self.start_time = time.time()
        self.total_attempts = 0

    # -- verification ----------------------------------------------------

    def verify(self, candidate: str) -> bool:
        """Return True if `candidate` hashes to `self.target_hash`."""
        if self.algorithm == "bcrypt":
            try:
                return bcrypt.checkpw(candidate.encode("utf-8"),
                                      self.target_hash.encode("utf-8"))
            except (ValueError, TypeError):
                return False
        return _hashlib_digest(candidate, self.algorithm) == self.target_hash.lower()

    async def _check(self, candidate: str) -> bool:
        """
        Verify a guess without stalling the event loop.

        bcrypt is deliberately slow (up to ~300 ms per check at cost 12), so it
        runs in a worker thread; the server keeps answering other connections
        meanwhile. Fast hashlib digests stay inline, where a thread hop would
        cost more than the hash itself.
        """
        if self.algorithm == "bcrypt":
            return await asyncio.to_thread(self.verify, candidate)
        return self.verify(candidate)

    async def measure_check_seconds(self) -> float:
        """Time one wrong-guess verification against the target hash (off the loop)."""
        start = time.perf_counter()
        await asyncio.to_thread(self.verify, "\x00not-a-real-guess")
        return time.perf_counter() - start

    def _bcrypt_limit_reached(self) -> dict | None:
        """Return an 'exhausted' update once a bcrypt run hits its cap, else None."""
        if self.algorithm != "bcrypt":
            return None
        elapsed = time.time() - self.start_time
        if self.total_attempts >= MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS:
            reason = f"bcrypt cap reached ({self.total_attempts} attempts)."
        elif elapsed >= MAX_BCRYPT_SECONDS:
            reason = f"bcrypt time budget reached ({MAX_BCRYPT_SECONDS:g} s)."
        else:
            return None
        return {
            "status": "exhausted",
            "message": f"{reason} Use dictionary mode for realistic bcrypt demos.",
            "total_attempts": self.total_attempts,
            "time_taken": round(elapsed, 4),
        }

    def _progress_due(self) -> bool:
        interval = (BCRYPT_PROGRESS_INTERVAL if self.algorithm == "bcrypt"
                    else PROGRESS_INTERVAL)
        return self.total_attempts % interval == 0

    # -- shared bookkeeping ---------------------------------------------

    def _progress(self, current_guess: str) -> dict:
        elapsed = max(time.time() - self.start_time, 1e-9)
        return {
            "status": "running",
            "current_guess": current_guess,
            "attempts": self.total_attempts,
            "elapsed": round(elapsed, 2),
            "speed": round(self.total_attempts / elapsed, 0),
        }

    def _complete(self, password: str) -> dict:
        elapsed = time.time() - self.start_time
        return {
            "status": "complete",
            "password": password,
            "total_attempts": self.total_attempts,
            "time_taken": round(elapsed, 4),
        }

    def _exhausted(self) -> dict:
        elapsed = time.time() - self.start_time
        return {
            "status": "exhausted",
            "message": "Search space exhausted without finding the password.",
            "total_attempts": self.total_attempts,
            "time_taken": round(elapsed, 4),
        }

    # -- brute force -----------------------------------------------------

    async def brute_force(
        self,
        charset_name: str = "lower",
        max_length: int = 4,
    ) -> AsyncIterator[dict]:
        """
        Try every candidate from `charset` of length 1..max_length.

        Raises SearchSpaceTooLargeError if the requested space exceeds the cap.
        For bcrypt, the run stops at MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS or
        MAX_BCRYPT_SECONDS, whichever comes first.
        """
        if charset_name not in CHARSETS:
            raise CrackerError(f"Unknown charset: {charset_name}")
        if max_length < 1:
            raise CrackerError("max_length must be >= 1")

        chars = CHARSETS[charset_name]
        search_space = sum(len(chars) ** L for L in range(1, max_length + 1))

        if search_space > MAX_BRUTE_FORCE_SEARCH_SPACE:
            raise SearchSpaceTooLargeError(
                f"Brute-force space ({search_space:,}) exceeds safety cap "
                f"({MAX_BRUTE_FORCE_SEARCH_SPACE:,}). Reduce max_length or use a smaller charset."
            )

        entropy = math.log2(search_space) if search_space > 0 else 0.0
        bcrypt_warning = None
        bcrypt_info: dict = {}
        if self.algorithm == "bcrypt":
            # Time one real check against this hash instead of assuming a speed:
            # the cost factor in the hash decides it (cost 12 is ~4x cost 10).
            per_check = await self.measure_check_seconds()
            cost = bcrypt_cost(self.target_hash)
            bcrypt_info = {"bcrypt_cost": cost, "seconds_per_check": round(per_check, 4)}
            cost_text = f"cost {cost}, " if cost is not None else ""
            bcrypt_warning = (
                f"bcrypt is intentionally slow. Brute-forcing this space "
                f"would take roughly {human_duration(search_space * per_check)} "
                f"({cost_text}{per_check * 1000:,.0f} ms/check measured on this server). "
                f"The run stops after {MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS} attempts "
                f"or {MAX_BCRYPT_SECONDS:g} s, whichever comes first."
            )

        starting = {
            "status": "starting",
            "method": "brute_force",
            "algorithm": self.algorithm,
            "charset": charset_name,
            "max_length": max_length,
            "search_space": search_space,
            "entropy": round(entropy, 2),
        }
        if bcrypt_warning:
            starting["warning"] = bcrypt_warning
            starting.update(bcrypt_info)
        yield starting
        await asyncio.sleep(0)

        for length in range(1, max_length + 1):
            for guess_tuple in itertools.product(chars, repeat=length):
                guess = "".join(guess_tuple)
                self.total_attempts += 1

                if await self._check(guess):
                    yield self._complete(guess)
                    return

                if (stop := self._bcrypt_limit_reached()) is not None:
                    yield stop
                    return

                if self._progress_due():
                    yield self._progress(guess)
                if self.total_attempts % YIELD_INTERVAL == 0:
                    await asyncio.sleep(0)

        yield self._exhausted()

    # -- dictionary ------------------------------------------------------

    async def dictionary(
        self,
        wordlist_path=None,
        words: Iterable[str] | None = None,
    ) -> AsyncIterator[dict]:
        """
        Try entries from a wordlist file (one word per line).

        If `words` is provided, it overrides `wordlist_path` (useful for tests).
        """
        if words is None:
            path = Path(wordlist_path) if wordlist_path else Path(__file__).parent / "wordlist.txt"
            if not path.exists():
                raise CrackerError(f"Wordlist not found at {path}")
            with path.open("r", encoding="utf-8") as fh:
                words = [w.strip() for w in fh if w.strip()]

        word_list = list(words)

        yield {
            "status": "starting",
            "method": "dictionary",
            "algorithm": self.algorithm,
            "search_space": len(word_list),
            "entropy": round(math.log2(len(word_list)), 2) if word_list else 0.0,
        }
        await asyncio.sleep(0)

        for word in word_list:
            self.total_attempts += 1
            if await self._check(word):
                yield self._complete(word)
                return
            if (stop := self._bcrypt_limit_reached()) is not None:
                yield stop
                return
            if self.total_attempts % 100 == 0 or (
                self.algorithm == "bcrypt" and self._progress_due()
            ):
                yield self._progress(word)
                await asyncio.sleep(0)

        yield self._exhausted()

    # -- mask ------------------------------------------------------------

    async def mask(self, mask: str) -> AsyncIterator[dict]:
        """
        Try every candidate matching a Hashcat-style mask.

        See `expand_mask` for the supported tokens.
        """
        positions = expand_mask(mask)
        search_space = 1
        for charset in positions:
            search_space *= len(charset)

        if search_space > MAX_BRUTE_FORCE_SEARCH_SPACE:
            raise SearchSpaceTooLargeError(
                f"Mask space ({search_space:,}) exceeds safety cap "
                f"({MAX_BRUTE_FORCE_SEARCH_SPACE:,})."
            )

        yield {
            "status": "starting",
            "method": "mask",
            "algorithm": self.algorithm,
            "mask": mask,
            "search_space": search_space,
            "entropy": round(math.log2(search_space), 2) if search_space > 0 else 0.0,
        }
        await asyncio.sleep(0)

        for guess_tuple in itertools.product(*positions):
            guess = "".join(guess_tuple)
            self.total_attempts += 1

            if await self._check(guess):
                yield self._complete(guess)
                return

            if (stop := self._bcrypt_limit_reached()) is not None:
                yield stop
                return

            if self._progress_due():
                yield self._progress(guess)
            if self.total_attempts % YIELD_INTERVAL == 0:
                await asyncio.sleep(0)

        yield self._exhausted()
