import asyncio
from simulator import CipherSimulator
import json

async def test_simulator():
    print("Testing CipherSimulator...")
    simulator = CipherSimulator("abc")
    
    print("Running brute_force_gen...")
    async for update in simulator.brute_force_gen():
        print(f"Update: {json.dumps(update)}")
        if update["status"] == "complete":
            print("Test passed: Password found!")
            return
    print("Test failed: Password not found.")

if __name__ == "__main__":
    asyncio.run(test_simulator())
