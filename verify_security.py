"""
Standalone security verification script for the Password Cracker Simulator.

This script manually tests the backend's security mechanisms:
1. Long password blocking (> 64 chars).
2. Concurrent connection limiting (max 5).

Usage:
    py verify_security.py run
"""

import asyncio
import json
import websockets
import sys

async def test_limits():
    """
    Asynchronous function that runs the manual verification checks.
    """
    uri = "ws://localhost:8000/ws/simulate"
    
    # 1. Test Long Password (Security Limit)
    print("Testing long password...")
    try:
        async with websockets.connect(uri) as ws:
            # Attempt to send a 100-character password
            await ws.send(json.dumps({"password": "a" * 100}))
            resp = await ws.recv()
            print(f"Long password response: {resp}")
            if "Password exceeds maximum length" in resp:
                print("SUCCESS: Long password blocked.")
            else:
                print("FAILURE: Long password NOT blocked.")
    except Exception as e:
        print(f"Long password test failed: {e}")

    # 2. Test Concurrent Connections (DoS Prevention)
    print("\nTesting concurrent connections...")
    connections = []
    for i in range(6):
        try:
            ws = await websockets.connect(uri)
            connections.append(ws)
            print(f"Opened connection {i+1}")
            if i < 5:
                # Keep first 5 connections active
                await ws.send(json.dumps({"password": "p"}))
            else:
                # The 6th connection should be rejected
                resp = await ws.recv()
                print(f"6th connection response: {resp}")
                if "Server busy" in resp:
                    print("SUCCESS: Connection limit reached.")
                else:
                    print("FAILURE: Connection limit NOT reached.")
        except Exception as e:
            print(f"Connection {i+1} trial failed: {e}")

    # Cleanup: Close all active sockets
    for ws in connections:
        try:
            await ws.close()
        except:
            pass

if __name__ == "__main__":
    # Entry point check
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        asyncio.run(test_limits())
    else:
        print("Usage: py verify_security.py run")
        print("Note: Ensure the backend is running (npm run dev:server)")
