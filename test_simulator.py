"""
Unit tests for the HashCracker engine.

Covers:
    * Hash verification for md5/sha1/sha256/bcrypt
    * Brute-force attack against a short hashed password
    * Dictionary attack against a known wordlist entry
    * Mask attack with the Hashcat-style ?l/?u/?d/?s/?a tokens
    * Search-space safety cap (raises SearchSpaceTooLargeError)
    * Mask validation (raises InvalidMaskError)
"""

from __future__ import annotations

import hashlib

import bcrypt
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from simulator import (
    CHARSETS,
    MASK_TOKENS,
    MAX_BRUTE_FORCE_SEARCH_SPACE,
    CrackerError,
    HashCracker,
    InvalidMaskError,
    SearchSpaceTooLargeError,
    _hashlib_digest,
    expand_mask,
)

# --- helpers ---------------------------------------------------------------

def _digest(plaintext: str, algorithm: str) -> str:
    return hashlib.new(algorithm, plaintext.encode("utf-8")).hexdigest()


async def _collect(generator) -> list[dict]:
    """Drain an async generator to a list - handy for assertions."""
    return [item async for item in generator]


# --- verification ----------------------------------------------------------

@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256"])
def test_verify_hashlib_algorithms(algorithm: str) -> None:
    target = _digest("hunter2", algorithm)
    cracker = HashCracker(target_hash=target, algorithm=algorithm)
    assert cracker.verify("hunter2") is True
    assert cracker.verify("nope") is False


def test_verify_bcrypt() -> None:
    target = bcrypt.hashpw(b"letmein", bcrypt.gensalt(rounds=4)).decode()
    cracker = HashCracker(target_hash=target, algorithm="bcrypt")
    assert cracker.verify("letmein") is True
    assert cracker.verify("wrong") is False


def test_unsupported_algorithm_raises() -> None:
    with pytest.raises(CrackerError):
        HashCracker(target_hash="x", algorithm="rot13")


# --- brute force -----------------------------------------------------------

@pytest.mark.asyncio
async def test_brute_force_finds_short_password() -> None:
    target = _digest("ab", "md5")
    cracker = HashCracker(target_hash=target, algorithm="md5")
    updates = await _collect(cracker.brute_force(charset_name="lower", max_length=2))

    assert updates[0]["status"] == "starting"
    assert updates[0]["method"] == "brute_force"
    final = updates[-1]
    assert final["status"] == "complete"
    assert final["password"] == "ab"


@pytest.mark.asyncio
async def test_brute_force_exhausts_when_no_match() -> None:
    # Hash of "zz" but we only search length 1 - cannot find it.
    target = _digest("zz", "md5")
    cracker = HashCracker(target_hash=target, algorithm="md5")
    updates = await _collect(cracker.brute_force(charset_name="lower", max_length=1))

    assert updates[-1]["status"] == "exhausted"


@pytest.mark.asyncio
async def test_brute_force_rejects_oversize_space() -> None:
    cracker = HashCracker(target_hash="x" * 32, algorithm="md5")
    # "all" charset (~94) ^ 8 is ~6e15 - massively above the cap.
    with pytest.raises(SearchSpaceTooLargeError):
        async for _ in cracker.brute_force(charset_name="all", max_length=8):
            pass


# --- dictionary ------------------------------------------------------------

@pytest.mark.asyncio
async def test_dictionary_finds_known_word() -> None:
    target = _digest("password", "sha256")
    cracker = HashCracker(target_hash=target, algorithm="sha256")
    updates = await _collect(
        cracker.dictionary(words=["123456", "password", "letmein"])
    )

    final = updates[-1]
    assert final["status"] == "complete"
    assert final["password"] == "password"


@pytest.mark.asyncio
async def test_dictionary_exhausts_when_no_match() -> None:
    target = _digest("definitelynotinlist", "sha256")
    cracker = HashCracker(target_hash=target, algorithm="sha256")
    updates = await _collect(cracker.dictionary(words=["alpha", "beta", "gamma"]))
    assert updates[-1]["status"] == "exhausted"


@pytest.mark.asyncio
async def test_dictionary_uses_bundled_wordlist_by_default() -> None:
    # "password" is in the bundled wordlist.txt
    target = _digest("password", "md5")
    cracker = HashCracker(target_hash=target, algorithm="md5")
    updates = await _collect(cracker.dictionary())
    assert updates[-1]["status"] == "complete"
    assert updates[-1]["password"] == "password"


# --- mask ------------------------------------------------------------------

def test_expand_mask_basic() -> None:
    positions = expand_mask("?l?d")
    assert positions == [CHARSETS["lower"], CHARSETS["digits"]]


def test_expand_mask_with_literals() -> None:
    positions = expand_mask("a?d")
    assert positions == ["a", CHARSETS["digits"]]


def test_expand_mask_rejects_dangling_question_mark() -> None:
    with pytest.raises(InvalidMaskError):
        expand_mask("?l?")


def test_expand_mask_rejects_unknown_token() -> None:
    with pytest.raises(InvalidMaskError):
        expand_mask("?z")


@pytest.mark.asyncio
async def test_mask_finds_known_pattern() -> None:
    target = _digest("ab12", "sha1")
    cracker = HashCracker(target_hash=target, algorithm="sha1")
    updates = await _collect(cracker.mask("?l?l?d?d"))

    final = updates[-1]
    assert final["status"] == "complete"
    assert final["password"] == "ab12"


@pytest.mark.asyncio
async def test_mask_rejects_oversize_space() -> None:
    cracker = HashCracker(target_hash="x" * 32, algorithm="md5")
    # ?a (94) ^ 6 = ~6.9e11 > cap
    with pytest.raises(SearchSpaceTooLargeError):
        async for _ in cracker.mask("?a?a?a?a?a?a?a?a"):
            pass


# --- search space cap sanity ----------------------------------------------

def test_search_space_cap_is_positive() -> None:
    assert MAX_BRUTE_FORCE_SEARCH_SPACE > 0


# --- property-based tests (Hypothesis) -------------------------------------
#
# These exercise the mask parser and HashCracker invariants against a wide,
# automatically-generated input space. They are intentionally lightweight so
# they finish in milliseconds even under CI.

# Strategy: a Hashcat-style mask built from valid tokens, with the parser only
# (we cap length so the cracker stays within search-space caps for any tests
# that exercise the engine downstream).
_mask_tokens = st.sampled_from(list(MASK_TOKENS.keys()))   # 'l', 'u', 'd', 's', 'a'
_literal_chars = st.text(alphabet="abcXYZ012_-", min_size=1, max_size=1)
_mask_atom = st.one_of(_mask_tokens.map(lambda t: f"?{t}"), _literal_chars)
_valid_masks = st.lists(_mask_atom, min_size=1, max_size=8).map("".join)


@given(_valid_masks)
def test_expand_mask_round_trip_length(mask: str) -> None:
    """Number of expanded positions equals the number of mask atoms."""
    positions = expand_mask(mask)

    # Count atoms in the mask the same way expand_mask does, so the property
    # is independent of the parser implementation.
    expected = 0
    i = 0
    while i < len(mask):
        if mask[i] == "?":
            expected += 1
            i += 2
        else:
            expected += 1
            i += 1
    assert len(positions) == expected


@given(_mask_tokens)
def test_expand_mask_single_token_yields_known_charset(token: str) -> None:
    """A single ?-token mask expands to the matching MASK_TOKENS charset."""
    positions = expand_mask(f"?{token}")
    assert positions == [MASK_TOKENS[token]]


@given(st.text(min_size=1, max_size=64))
def test_expand_mask_handles_arbitrary_strings(mask: str) -> None:
    """For any string, expand_mask either returns positions or raises InvalidMaskError - never crashes."""
    try:
        positions = expand_mask(mask)
        assert isinstance(positions, list) and positions
        # Every position must be a non-empty string (charset or literal char).
        assert all(isinstance(p, str) and len(p) >= 1 for p in positions)
    except InvalidMaskError:
        pass  # acceptable; the parser rejected the input cleanly


@given(st.text(min_size=0, max_size=32), st.sampled_from(["md5", "sha1", "sha256"]))
def test_hashlib_digest_is_deterministic_and_hex(candidate: str, algorithm: str) -> None:
    """Hashing the same input twice yields the same hex digest of the expected length."""
    a = _hashlib_digest(candidate, algorithm)
    b = _hashlib_digest(candidate, algorithm)
    assert a == b
    assert all(c in "0123456789abcdef" for c in a)
    # Digest size in hex chars: md5=32, sha1=40, sha256=64.
    expected_len = {"md5": 32, "sha1": 40, "sha256": 64}[algorithm]
    assert len(a) == expected_len


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    charset_name=st.sampled_from(list(CHARSETS.keys())),
    max_length=st.integers(min_value=1, max_value=4),
)
def test_brute_force_search_space_matches_formula(charset_name: str, max_length: int) -> None:
    """
    The starting event reports a search_space equal to sum(N^L for L in 1..max_length)
    where N = len(charset). Property: independent recomputation matches.
    """
    import asyncio

    async def first_event() -> dict:
        cracker = HashCracker(target_hash="0" * 64, algorithm="sha256")
        gen = cracker.brute_force(charset_name=charset_name, max_length=max_length)
        async for upd in gen:
            return upd
        raise AssertionError("generator produced no events")

    try:
        event = asyncio.run(first_event())
    except SearchSpaceTooLargeError:
        # Above-cap combos are allowed to be refused; the test passes trivially.
        return

    N = len(CHARSETS[charset_name])
    expected = sum(N ** L for L in range(1, max_length + 1))
    assert event["search_space"] == expected


# --- bcrypt must not block the event loop ----------------------------------

async def _max_loop_gap(coro) -> float:
    """Run `coro` next to a 10 ms ticker and return the longest stall seen."""
    import asyncio
    import time

    gaps: list[float] = []
    done = asyncio.Event()

    async def ticker() -> None:
        last = time.perf_counter()
        while not done.is_set():
            await asyncio.sleep(0.01)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    tick = asyncio.create_task(ticker())
    try:
        await coro
    finally:
        done.set()
        await tick
    return max(gaps) if gaps else 0.0


@pytest.mark.asyncio
async def test_bcrypt_brute_force_does_not_block_event_loop(monkeypatch) -> None:
    """Each bcrypt check runs off the loop, so other connections keep being served."""
    import simulator

    monkeypatch.setattr(simulator, "MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS", 12)
    target = bcrypt.hashpw(b"zz", bcrypt.gensalt(rounds=10)).decode()  # ~70 ms/check
    cracker = HashCracker(target_hash=target, algorithm="bcrypt")
    gap = await _max_loop_gap(_collect(cracker.brute_force("lower", 2)))
    assert gap < 0.25, f"event loop stalled for {gap:.2f}s"


@pytest.mark.asyncio
async def test_bcrypt_mask_attack_is_capped(monkeypatch) -> None:
    """Mask mode against bcrypt stops at the attempt cap instead of running for hours."""
    import simulator

    monkeypatch.setattr(simulator, "MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS", 20)
    target = bcrypt.hashpw(b"zzz", bcrypt.gensalt(rounds=4)).decode()
    cracker = HashCracker(target_hash=target, algorithm="bcrypt")
    updates = await _collect(cracker.mask("?l?l?l"))
    assert updates[-1]["status"] == "exhausted"
    assert updates[-1]["total_attempts"] == 20


@pytest.mark.asyncio
async def test_bcrypt_time_budget_stops_attack(monkeypatch) -> None:
    """A wall-clock budget ends a bcrypt run even before the attempt cap."""
    import simulator

    monkeypatch.setattr(simulator, "MAX_BCRYPT_SECONDS", 0.3)
    target = bcrypt.hashpw(b"zz", bcrypt.gensalt(rounds=10)).decode()
    cracker = HashCracker(target_hash=target, algorithm="bcrypt")
    updates = await _collect(cracker.brute_force("lower", 2))
    assert updates[-1]["status"] == "exhausted"
    assert updates[-1]["total_attempts"] < simulator.MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS


# --- measured bcrypt estimate ------------------------------------------------

@pytest.mark.parametrize("prefix,cost", [("$2b$12$", 12), ("$2a$04$", 4), ("$2y$10$", 10)])
def test_bcrypt_cost_is_read_from_hash(prefix: str, cost: int) -> None:
    from simulator import bcrypt_cost

    assert bcrypt_cost(prefix + "x" * 53) == cost


def test_bcrypt_cost_none_for_non_bcrypt() -> None:
    from simulator import bcrypt_cost

    assert bcrypt_cost(_digest("abc", "sha256")) is None


@pytest.mark.asyncio
async def test_bcrypt_estimate_uses_measured_speed(monkeypatch) -> None:
    """The warning reports the hash's real cost and a measured per-check time."""
    import simulator

    monkeypatch.setattr(simulator, "MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS", 3)
    target = bcrypt.hashpw(b"zz", bcrypt.gensalt(rounds=4)).decode()
    cracker = HashCracker(target_hash=target, algorithm="bcrypt")
    starting = (await _collect(cracker.brute_force("lower", 2)))[0]
    assert starting["bcrypt_cost"] == 4
    assert 0 < starting["seconds_per_check"] < 0.5
    assert "cost 4" in starting["warning"]
    assert "50ms" not in starting["warning"]


@pytest.mark.parametrize("seconds,expected", [
    (59, "59 seconds"), (7200, "2.0 hours"), (126_417, "1.5 days"), (3 * 31_536_000, "3.0 years"),
])
def test_human_duration(seconds: float, expected: str) -> None:
    from simulator import human_duration

    assert human_duration(seconds) == expected


# --- argon2id and pbkdf2 as crackable (slow) algorithms ----------------------

@pytest.mark.asyncio
async def test_dictionary_cracks_argon2id() -> None:
    """A weak password still falls to a dictionary attack under Argon2id."""
    from argon2 import PasswordHasher

    target = PasswordHasher().hash("qwerty")
    cracker = HashCracker(target_hash=target, algorithm="argon2id")
    assert cracker.is_slow is True
    updates = await _collect(cracker.dictionary())
    assert updates[-1]["status"] == "complete"
    assert updates[-1]["password"] == "qwerty"


@pytest.mark.asyncio
async def test_dictionary_cracks_pbkdf2() -> None:
    """Same lesson for PBKDF2: a strong KDF does not save a wordlist password."""
    import os

    from simulator import pbkdf2_encode

    target = pbkdf2_encode("letmein", os.urandom(16), 50_000)
    cracker = HashCracker(target_hash=target, algorithm="pbkdf2_sha256")
    assert cracker.verify("letmein") is True
    assert cracker.verify("nope") is False
    updates = await _collect(cracker.dictionary())
    assert updates[-1]["password"] == "letmein"


@pytest.mark.asyncio
async def test_argon2id_brute_force_is_capped(monkeypatch) -> None:
    """Argon2id brute force shares the slow-KDF attempt cap (no infinite spin)."""
    from argon2 import PasswordHasher

    import simulator

    monkeypatch.setattr(simulator, "MAX_BCRYPT_BRUTE_FORCE_ATTEMPTS", 15)
    target = PasswordHasher(memory_cost=8, time_cost=1, parallelism=1).hash("zzz")
    cracker = HashCracker(target_hash=target, algorithm="argon2id")
    updates = await _collect(cracker.brute_force("lower", 3))
    assert updates[-1]["status"] == "exhausted"
    assert updates[-1]["total_attempts"] == 15
    assert "argon2id" in updates[0]["warning"]
