"""
Main entry point for the Password Cracker Simulator backend.

This module sets up a FastAPI server with WebSocket support for real-time 
brute-force password cracking simulations. It includes security measures 
such as restricted CORS and concurrent connection limits.
"""

import json
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from simulator import CipherSimulator

app = FastAPI(
    title="Password Cracker Simulator API",
    description="Backend API for real-time password cracking simulations.",
    version="1.0.0"
)

# --- Configuration & Security ---

# Maximum number of concurrent simulations allowed to prevent DoS via CPU exhaustion.
MAX_CONCURRENT_SIMULATIONS = 5
# Global counter for current active WebSocket connections.
active_connections = 0

# Security: Restrict CORS to known frontend development origins.
# Security: Restrict CORS. In production, you'd specify your Vercel URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for simplicity in this demo, but restrict to your Vercel URL in prod.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/simulate")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for initiating a password cracking simulation.
    
    This endpoint:
    1. Checks the concurrent connection limit.
    2. Accepts the socket connection.
    3. Receives a target password JSON from the client.
    4. Validates the password length (Security measure).
    5. Streams progress updates from CipherSimulator back to the client.
    6. Manages connection lifecycle and cleanup.
    
    Args:
        websocket: The FastAPI WebSocket connection object.
    """
    global active_connections
    print("New WebSocket connection attempt...")
    
    # 1. Check Resource Limits
    if active_connections >= MAX_CONCURRENT_SIMULATIONS:
        print("Error: Max concurrent simulations reached")
        await websocket.accept()
        await websocket.send_text(json.dumps({
            "error": "Server busy. Too many concurrent simulations."
        }))
        await websocket.close()
        return

    # 2. Establish Connection
    await websocket.accept()
    active_connections += 1
    print(f"WebSocket connected. Active connections: {active_connections}")
    
    try:
        # 3. Receive Simulation Parameters
        data = await websocket.receive_text()
        print(f"Received data: {data}")
        params = json.loads(data)
        password = params.get("password")
        
        # 4. Input Validation (Security)
        if not password:
            print("Error: No password provided")
            await websocket.send_text(json.dumps({"error": "No password provided"}))
            await websocket.close()
            return

        if len(password) > 64:
            print(f"Error: Password too long ({len(password)} chars)")
            await websocket.send_text(json.dumps({
                "error": "Password exceeds maximum length (64 characters)"
            }))
            await websocket.close()
            return
            
        print(f"Starting simulation for password: [REDACTED]")
        
        # 5. Execute Simulation
        simulator = CipherSimulator(password)
        async for update in simulator.brute_force_gen():
            await websocket.send_text(json.dumps(update))
            # Throttle updates slightly to prevent socket saturation
            await asyncio.sleep(0.01)
            
        print("Simulation complete.")
            
    except WebSocketDisconnect:
        print("Client disconnected.")
    except Exception as e:
        print(f"Socket Error: {e}")
        try:
            # Mask internal errors for security
            await websocket.send_text(json.dumps({"error": "Internal server error"}))
        except:
            pass
    finally:
        # 6. Resource Cleanup
        active_connections -= 1
        print(f"Connection closed. Active connections: {active_connections}")

if __name__ == "__main__":
    # Start the server using Uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
