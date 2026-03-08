"""
Automated security tests for the Password Cracker Simulator backend.

This module contains pytest-asyncio based tests to verify that 
resource limits and input validation are functioning correctly.
"""

import asyncio
import json
import websockets
import pytest
import multiprocessing
import time
from main import app
import uvicorn

def run_server():
    """Starts the FastAPI server on a test port."""
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="error")

@pytest.fixture(scope="module")
def server():
    """
    Module-level fixture that starts the backend server in a separate 
    process and terminates it after tests are finished.
    """
    proc = multiprocessing.Process(target=run_server, daemon=True)
    proc.start()
    time.sleep(1)  # Wait for server to start
    yield
    proc.terminate()

@pytest.mark.asyncio
async def test_password_length_limit(server):
    """
    Verifies that the backend correctly rejects passwords longer than 64 characters.
    """
    uri = "ws://127.0.0.1:8001/ws/simulate"
    async with websockets.connect(uri) as websocket:
        # 65 character password
        long_password = "a" * 65
        await websocket.send(json.dumps({"password": long_password}))
        response = await websocket.recv()
        data = json.loads(response)
        assert "error" in data
        assert "exceeds maximum length" in data

@pytest.mark.asyncio
async def test_concurrent_connection_limit(server):
    """
    Verifies that the backend correctly enforces the concurrent connection limit (5).
    """
    uri = "ws://127.0.0.1:8001/ws/simulate"
    connections = []
    
    # Try to open 6 connections (limit is 5)
    for i in range(6):
        try:
            ws = await websockets.connect(uri)
            connections.append(ws)
            # Send valid password for first 5
            if i < 5:
                await ws.send(json.dumps({"password": "test"}))
        except Exception as e:
            if i == 5:
                # The 6th connection might fail at the handshake or send an error then close
                pass
            else:
                pytest.fail(f"Connection {i} failed unexpectedly: {e}")

    # The 6th one should have received an error message if it accepted then closed
    ws6 = await websockets.connect(uri)
    response = await ws6.recv()
    data = json.loads(response)
    assert "error" in data
    assert "Server busy" in data
    
    # Cleanup
    for ws in connections:
        await ws.close()
    await ws6.close()

if __name__ == "__main__":
    # Provides instructions for running the tests via terminal
    print("Run with: pytest test_security.py")
