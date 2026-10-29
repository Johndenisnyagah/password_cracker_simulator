"""Tests for the OWASP password-storage auditor."""

from __future__ import annotations

import base64
import hashlib

import bcrypt
import pytest
from argon2 import PasswordHasher

from storage_audit import (
    ARGON2_MIN_MEMORY_KIB,
    BCRYPT_MIN_COST,
    PBKDF2_SHA256_MIN_ITERATIONS,
    audit_hash,
)


def test_bcrypt_at_min_cost_is_strong() -> None:
    h = bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=BCRYPT_MIN_COST)).decode()
    r = audit_hash(h)
    assert r["algorithm"] == "bcrypt"
    assert r["verdict"] == "strong"
    assert r["details"]["cost"] == BCRYPT_MIN_COST


def test_bcrypt_below_min_cost_is_weak() -> None:
    h = bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=6)).decode()
    r = audit_hash(h)
    assert r["verdict"] == "weak"
    assert "work factor" in r["recommendation"]


def test_argon2id_default_is_strong() -> None:
    h = PasswordHasher().hash("x")  # library defaults exceed OWASP minimums
    r = audit_hash(h)
    assert r["algorithm"] == "argon2id"
    assert r["verdict"] == "strong"
    assert r["details"]["memory_kib"] >= ARGON2_MIN_MEMORY_KIB


def test_argon2id_underpowered_is_weak() -> None:
    h = PasswordHasher(memory_cost=1024, time_cost=1, parallelism=1).hash("x")
    r = audit_hash(h)
    assert r["verdict"] == "weak"
    assert "memory" in r["recommendation"]


def test_argon2i_variant_flagged() -> None:
    from argon2 import Type

    h = PasswordHasher(type=Type.I).hash("x")
    r = audit_hash(h)
    assert r["verdict"] == "weak"
    assert "Argon2id" in r["recommendation"]


def test_pbkdf2_strong_and_weak() -> None:
    def enc(iters: int) -> str:
        salt = b"0123456789abcdef"
        dk = hashlib.pbkdf2_hmac("sha256", b"x", salt, iters)
        b64 = lambda raw: base64.b64encode(raw).decode()
        return f"pbkdf2_sha256${iters}${b64(salt)}${b64(dk)}"

    assert audit_hash(enc(PBKDF2_SHA256_MIN_ITERATIONS))["verdict"] == "strong"
    assert audit_hash(enc(1000))["verdict"] == "weak"


@pytest.mark.parametrize("text,name", [
    (hashlib.md5(b"x").hexdigest(), "MD5"),
    (hashlib.sha1(b"x").hexdigest(), "SHA-1"),
    (hashlib.sha256(b"x").hexdigest(), "SHA-256"),
])
def test_fast_hashes_are_unsuitable(text: str, name: str) -> None:
    r = audit_hash(text)
    assert r["verdict"] == "unsuitable"
    assert name in r["summary"]


def test_empty_and_garbage() -> None:
    assert audit_hash("")["verdict"] == "unknown"
    assert audit_hash("not-a-hash")["verdict"] == "unknown"
