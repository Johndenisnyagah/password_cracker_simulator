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
import string
import time
from pathlib import Path
from typing import AsyncIterator, Iterable

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

# Hard safety cap on brute-force search space. ~308M candidates is roughly
# one minute of work at 5M guesses/sec - large enough to demo, small enough
# that the server cannot be tied up indefinitely.
MAX_BRUTE_FORCE_SEARCH_SPACE = 26 ** 6  # 308,915,776

# Bcrypt is intentionally slow. A brute-force attack is essentially intractable,
# so we refuse anything larger than a token sample.
MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS = 500

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
        For bcrypt, attempts are additionally capped at MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS.
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
        if self.algorithm == "bcrypt":
            est_seconds = search_space * 0.05
            est_years = est_seconds / (60 * 60 * 24 * 365)
            bcrypt_warning = (
                f"bcrypt is intentionally slow. Brute-forcing this space "
                f"would take roughly {est_years:,.1f} years at ~50ms/check. "
                f"Attempts will be capped at {MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS}."
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
        yield starting
        await asyncio.sleep(0)

        attempt_cap = (
            MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS if self.algorithm == "bcrypt" else None
        )

        for length in range(1, max_length + 1):
            for guess_tuple in itertools.product(chars, repeat=length):
                guess = "".join(guess_tuple)
                self.total_attempts += 1

                if self.verify(guess):
                    yield self._complete(guess)
                    return

                if attempt_cap is not None and self.total_attempts >= attempt_cap:
                    yield {
                        "status": "exhausted",
                        "message": (
                            f"bcrypt cap reached ({attempt_cap} attempts). "
                            "Use dictionary mode for realistic bcrypt demos."
                        ),
                        "total_attempts": self.total_attempts,
                        "time_taken": round(time.time() - self.start_time, 4),
                    }
                    return

                if self.total_attempts % PROGRESS_INTERVAL == 0:
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
            if self.verify(word):
                yield self._complete(word)
                return
            if self.total_attempts % 100 == 0:
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

            if self.verify(guess):
                yield self._complete(guess)
                return

            if self.total_attempts % PROGRESS_INTERVAL == 0:
                yield self._progress(guess)
            if self.total_attempts % YIELD_INTERVAL == 0:
                await asyncio.sleep(0)

        yield self._exhausted()
