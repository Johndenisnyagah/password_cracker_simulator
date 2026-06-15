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

from simulator import (
    CHARSETS,
    CrackerError,
    HashCracker,
    InvalidMaskError,
    MAX_BRUTE_FORCE_SEARCH_SPACE,
    SearchSpaceTooLargeError,
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
