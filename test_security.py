"""
Automated security tests for the Password Cracker Simulator backend.

Verifies:
    * Invalid payloads (missing required fields) are rejected with a
      structured error rather than a 500.
    * Unsupported algorithms are rejected by Pydantic validation.
    * Brute-force search-space cap returns an error update rather than
      tying up the server.

The concurrent-connection limit is exercised by an end-to-end demo script in
the README; encoding it as a unit test requires holding 5 long-running sockets
open which makes the test suite slow and flaky in CI. The cap itself is
exercised in test_simulator.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import multiprocessing
import socket
import time

import bcrypt
import pytest
import uvicorn
import websockets

from main import app


def _free_port() -> int:
    """Pick a free local port so parallel test runs don\'t collide."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_PORT = _free_port()


def _run_server() -> None:
    uvicorn.run(app, host="127.0.0.1", port=_PORT, log_level="error")


@pytest.fixture(scope="module")
def server():
    """Start the FastAPI app in a subprocess for the duration of the module."""
    proc = multiprocessing.Process(target=_run_server, daemon=True)
    proc.start()
    # Poll for readiness rather than sleep blindly.
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", _PORT), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    yield
    proc.terminate()
    proc.join(timeout=2)


def _uri() -> str:
    return f"ws://127.0.0.1:{_PORT}/ws/simulate"


@pytest.mark.asyncio
async def test_invalid_payload_returns_validation_error(server) -> None:
    """Payload missing required fields gets a structured error, not a crash."""
    async with websockets.connect(_uri()) as ws:
        await ws.send(json.dumps({"hash": "abc"}))  # missing algorithm + attack_mode
        data = json.loads(await ws.recv())
        assert data["status"] == "error"
        assert "Invalid request payload" in data["error"]
        assert "details" in data


@pytest.mark.asyncio
async def test_invalid_json_returns_error(server) -> None:
    """Non-JSON payload is rejected cleanly."""
    async with websockets.connect(_uri()) as ws:
        await ws.send("this is not json")
        data = json.loads(await ws.recv())
        assert data["status"] == "error"
        assert "Invalid JSON" in data["error"]


@pytest.mark.asyncio
async def test_unsupported_algorithm_rejected(server) -> None:
    """Pydantic Literal blocks unknown algorithms before they reach the engine."""
    async with websockets.connect(_uri()) as ws:
        target = hashlib.sha256(b"abc").hexdigest()
        await ws.send(json.dumps({
            "hash": target,
            "algorithm": "rot13",
            "attack_mode": "brute_force",
        }))
        data = json.loads(await ws.recv())
        assert data["status"] == "error"


@pytest.mark.asyncio
async def test_brute_force_search_space_cap(server) -> None:
    """An over-large brute-force request is refused with a SearchSpaceTooLargeError."""
    async with websockets.connect(_uri()) as ws:
        await ws.send(json.dumps({
            "hash": "0" * 64,
            "algorithm": "sha256",
            "attack_mode": "brute_force",
            "charset": "all",
            "max_length": 8,
        }))
        data = json.loads(await ws.recv())
        assert data["status"] == "error"
        assert "exceeds safety cap" in data["error"]


@pytest.mark.asyncio
async def test_valid_brute_force_finds_short_hash(server) -> None:
    """End-to-end happy path: server cracks a short hashed password."""
    target = hashlib.md5(b"ab").hexdigest()
    async with websockets.connect(_uri()) as ws:
        await ws.send(json.dumps({
            "hash": target,
            "algorithm": "md5",
            "attack_mode": "brute_force",
            "charset": "lower",
            "max_length": 2,
        }))
        # Drain updates until completion.
        final = None
        async for msg in ws:
            data = json.loads(msg)
            final = data
            if data.get("status") in ("complete", "exhausted", "error"):
                break
        assert final is not None
        assert final["status"] == "complete"
        assert final["password"] == "ab"


_SHA256_PASSWORD = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"


@pytest.mark.asyncio
async def test_foreign_origin_websocket_is_rejected(server) -> None:
    """Cross-site WebSocket hijacking (CWE-1385): a page on another origin must
    not be able to open the socket. CORSMiddleware does not cover WebSockets,
    so the endpoint checks the Origin header itself."""
    with pytest.raises(websockets.exceptions.InvalidStatusCode) as exc:
        async with websockets.connect(_uri(), origin="https://evil.example"):
            pass
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_allowed_origin_websocket_is_accepted(server) -> None:
    """The dashboard's own origin (from CORS_ORIGINS) still connects."""
    async with websockets.connect(_uri(), origin="http://localhost:5173") as ws:
        await ws.send(json.dumps({
            "hash": _SHA256_PASSWORD, "algorithm": "sha256", "attack_mode": "dictionary",
        }))
        final = None
        async for msg in ws:
            final = json.loads(msg)
            if final["status"] in ("complete", "exhausted", "error"):
                break
    assert final is not None and final["password"] == "password"

@pytest.mark.asyncio
async def test_health_stays_responsive_during_bcrypt_attack(server) -> None:
    """A slow bcrypt job must not freeze the server for everyone else.

    Before the fix, a cost-12 bcrypt brute force held the event loop so long
    that /health took 134 s to answer and the client was dropped.
    """
    import urllib.request

    target = bcrypt.hashpw(b"zz", bcrypt.gensalt(rounds=10)).decode()  # ~70 ms/check

    def health_latency() -> float:
        start = time.perf_counter()
        with urllib.request.urlopen(f"http://127.0.0.1:{_PORT}/health", timeout=10) as r:
            r.read()
        return time.perf_counter() - start

    async with websockets.connect(_uri()) as ws:
        await ws.send(json.dumps({
            "hash": target,
            "algorithm": "bcrypt",
            "attack_mode": "brute_force",
            "charset": "lower",
            "max_length": 1,  # 26 checks, ~2 s
        }))
        await ws.recv()  # "starting": the job is now running
        latency = await asyncio.to_thread(health_latency)
        final = None
        async for msg in ws:
            final = json.loads(msg)
            if final.get("status") in ("complete", "exhausted", "error"):
                break

    assert latency < 0.5, f"/health took {latency:.2f}s during a bcrypt job"
    assert final is not None and final["status"] == "exhausted"


@pytest.mark.asyncio
async def test_audit_endpoint_grades_a_hash(server) -> None:
    """POST /audit returns an OWASP verdict for a pasted hash."""
    import urllib.request

    weak = hashlib.md5(b"secret").hexdigest()

    def post() -> dict:
        body = json.dumps({"hash": weak}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{_PORT}/audit", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as resp:
            return json.loads(resp.read())

    result = await asyncio.to_thread(post)
    assert result["verdict"] == "unsuitable"
    assert result["algorithm"] == "md5"


if __name__ == "__main__":
    print("Run with: pytest test_security.py")
