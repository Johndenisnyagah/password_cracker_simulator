"""
Main entry point for the Password Cracker Simulator backend.

Exposes a single WebSocket endpoint that accepts an AttackRequest payload and
streams cracking progress updates back to the client. Supports three attack
modes (brute force, dictionary, mask) and four hash algorithms (md5, sha1,
sha256, bcrypt) via the HashCracker engine.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Literal, Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError

from simulator import (
    CrackerError,
    HashCracker,
    InvalidMaskError,
    SearchSpaceTooLargeError,
    SUPPORTED_ALGORITHMS,
)

app = FastAPI(
    title="Password Cracker Simulator API",
    description="Backend API for educational hash-cracking simulations.",
    version="2.0.0",
)

# --- Configuration & security ----------------------------------------------

# Cap on concurrent simulations to prevent CPU exhaustion. Enforced with an
# asyncio.Semaphore (race-free, unlike a bare global counter).
MAX_CONCURRENT_SIMULATIONS = 5
simulation_slots = asyncio.Semaphore(MAX_CONCURRENT_SIMULATIONS)

# CORS: restrict to known origins in production. Read from CORS_ORIGINS env var
# (comma-separated). Default to local dev origins so the demo works out of the
# box without footgunning prod.
_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("CORS_ORIGINS", _default_origins).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --- Inbound payload schema ------------------------------------------------

class AttackRequest(BaseModel):
    """Schema for a single cracking request received over the WebSocket."""

    hash: str = Field(..., min_length=1, max_length=256,
                      description="Target hash to crack (hex digest or bcrypt string).")
    algorithm: Literal["md5", "sha1", "sha256", "bcrypt"] = Field(
        ..., description="Hash algorithm used to produce the target hash.")
    attack_mode: Literal["brute_force", "dictionary", "mask"] = Field(
        ..., description="Which attack strategy to run.")

    # brute_force params
    charset: Literal["lower", "upper", "digits", "alphanumeric", "all"] = "lower"
    max_length: int = Field(default=4, ge=1, le=8)

    # mask param
    mask: Optional[str] = Field(default=None, max_length=32)


# --- Routes ----------------------------------------------------------------

@app.get("/health")
async def health_check() -> dict:
    """Lightweight health check for uptime monitors and Render warmup."""
    active = MAX_CONCURRENT_SIMULATIONS - simulation_slots._value
    return {
        "status": "ok",
        "active_connections": active,
        "max_concurrent": MAX_CONCURRENT_SIMULATIONS,
        "supported_algorithms": list(SUPPORTED_ALGORITHMS),
    }


async def _stream_updates(websocket: WebSocket, generator) -> None:
    """Forward updates from an async generator to the websocket as JSON."""
    async for update in generator:
        await websocket.send_text(json.dumps(update))
        # Tiny throttle to keep the client UI responsive.
        await asyncio.sleep(0.01)


async def _run_attack(websocket: WebSocket, req: AttackRequest) -> None:
    """Build the cracker and dispatch to the requested attack mode."""
    cracker = HashCracker(target_hash=req.hash, algorithm=req.algorithm)

    if req.attack_mode == "brute_force":
        gen = cracker.brute_force(charset_name=req.charset, max_length=req.max_length)
    elif req.attack_mode == "dictionary":
        gen = cracker.dictionary()
    elif req.attack_mode == "mask":
        if not req.mask:
            raise CrackerError("attack_mode=mask requires a non-empty 'mask' field")
        gen = cracker.mask(req.mask)
    else:  # pragma: no cover - Pydantic Literal blocks this
        raise CrackerError(f"Unknown attack_mode: {req.attack_mode}")

    await _stream_updates(websocket, gen)


@app.websocket("/ws/simulate")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """
    Receive an AttackRequest payload then stream cracking progress updates.

    Lifecycle:
        1. Accept the connection (so we can send a meaningful error if busy).
        2. Try to acquire a simulation slot - reject immediately if at capacity.
        3. Receive + validate the AttackRequest payload.
        4. Dispatch to the requested attack mode and stream updates.
        5. Release the slot on close (success, error, or disconnect).
    """
    await websocket.accept()

    # Try to acquire a slot without blocking - reject explicitly when full.
    if simulation_slots._value == 0:
        await websocket.send_text(json.dumps({
            "status": "error",
            "error": "Server busy. Too many concurrent simulations.",
        }))
        await websocket.close()
        return

    async with simulation_slots:
        try:
            raw = await websocket.receive_text()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "status": "error", "error": "Invalid JSON payload."
                }))
                return

            try:
                req = AttackRequest.model_validate(payload)
            except ValidationError as exc:
                await websocket.send_text(json.dumps({
                    "status": "error",
                    "error": "Invalid request payload.",
                    "details": exc.errors(include_url=False, include_input=False),
                }))
                return

            await _run_attack(websocket, req)

        except SearchSpaceTooLargeError as exc:
            await websocket.send_text(json.dumps({
                "status": "error", "error": str(exc),
            }))
        except InvalidMaskError as exc:
            await websocket.send_text(json.dumps({
                "status": "error", "error": f"Invalid mask: {exc}",
            }))
        except CrackerError as exc:
            await websocket.send_text(json.dumps({
                "status": "error", "error": str(exc),
            }))
        except WebSocketDisconnect:
            return
        except Exception as exc:  # noqa: BLE001
            # Don\'t leak internal details; surface them server-side only.
            print(f"[websocket] unexpected error: {exc!r}")
            try:
                await websocket.send_text(json.dumps({
                    "status": "error", "error": "Internal server error.",
                }))
            except Exception:  # pragma: no cover
                pass
        finally:
            try:
                await websocket.close()
            except Exception:  # pragma: no cover
                pass


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
