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
from hypothesis import HealthCheck, given, settings, strategies as st

from simulator import (
    CHARSETS,
    CrackerError,
    HashCracker,
    InvalidMaskError,
    MASK_TOKENS,
    MAX_BRUTE_FORCE_SEARCH_SPACE,
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
