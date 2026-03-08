"""
Core simulation engine for the Password Cracker Simulator.

This module contains the CipherSimulator class, which handles entropy 
calculations and the asynchronous brute-force search simulation.
"""

import time
import json
import asyncio
import itertools
import string
import math

class CipherSimulator:
    """
    Simulates a brute-force attack on a target password.
    
    Attributes:
        target_password (str): The password to be "cracked".
        start_time (float): The timestamp when the simulation started.
        total_attempts (int): Counter for the number of guesses attempted.
    """
    
    def __init__(self, target_password):
        """
        Initializes the CipherSimulator with a target password.
        
        Args:
            target_password (str): The password to simulate cracking for.
        """
        self.target_password = target_password
        self.start_time = time.time()
        self.total_attempts = 0
        
    def calculate_entropy(self):
        """
        Calculates the Shannon entropy and search space of the target password.
        
        The entropy is calculated based on the character sets present in 
         the password (lowercase, uppercase, digits, punctuation).
        
        Returns:
            tuple: (entropy_bits, charset_size)
        """
        length = len(self.target_password)
        charset_size = 0
        if any(c in string.ascii_lowercase for c in self.target_password): charset_size += 26
        if any(c in string.ascii_uppercase for c in self.target_password): charset_size += 26
        if any(c in string.digits for c in self.target_password): charset_size += 10
        if any(c in string.punctuation for c in self.target_password): charset_size += len(string.punctuation)
        
        # Calculate bits of entropy: log2(charset_size ^ length)
        entropy = math.log2(charset_size ** length) if charset_size > 0 else 0
        return entropy, charset_size

    async def brute_force_gen(self):
        """
        Asynchronous generator that simulates a brute-force search.
        
        Yields progress updates as dictionaries. These updates include:
        - status: 'starting', 'running', 'complete', or 'error'
        - method: the cracking strategy used
        - current_guess: the latest string trial (every 100k attempts)
        - attempts: total guesses so far
        - speed: guesses per second
        - password: the finally "found" password (in 'complete' status)
        
        Yields:
            dict: progress or completion data for the frontend.
        """
        if not self.target_password:
            yield {"status": "error", "error": "Empty password"}
            return

        chars = string.ascii_letters + string.digits + string.punctuation
        entropy, charset_size = self.calculate_entropy()
        
        # Initial search space results
        yield {
            "status": "starting",
            "method": "brute_force",
            "entropy": round(entropy, 2),
            "search_space": charset_size ** len(self.target_password)
        }

        # Yield initially to allow the event loop to breathe
        await asyncio.sleep(0)

        # Iterate through search space lengths
        for length in range(1, len(self.target_password) + 1):
            for guess_tuple in itertools.product(chars, repeat=length):
                guess = "".join(guess_tuple)
                self.total_attempts += 1
                
                # Check for direct match
                if guess == self.target_password:
                    elapsed = time.time() - self.start_time
                    yield {
                        "status": "complete",
                        "password": guess,
                        "total_attempts": self.total_attempts,
                        "time_taken": round(elapsed, 4)
                    }
                    return

                # Throttle progress reporting to avoid UI lag (every 100k attempts)
                if self.total_attempts % 100000 == 0:
                    elapsed = time.time() - self.start_time
                    yield {
                        "status": "running",
                        "current_guess": guess,
                        "attempts": self.total_attempts,
                        "elapsed": round(elapsed, 2),
                        "speed": round(self.total_attempts / elapsed, 0) if elapsed > 0 else 0
                    }
                    # Give control back to the event loop
                    await asyncio.sleep(0)
