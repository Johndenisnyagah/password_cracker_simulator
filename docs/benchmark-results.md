# Benchmark results

Measured on 2026-10-29 with `python scripts/benchmark.py` (a Linux cloud container, x86_64, Python 3.13, one core).

| Algorithm | Measured speed | Time to try all 26^6 lowercase 6-char passwords |
|---|---|---|
| md5 | 966,425 guesses/s | 320 s |
| sha1 | 974,504 guesses/s | 317 s |
| sha256 | 929,522 guesses/s | 332 s |
| bcrypt cost 4 | 1 ms/check | 4.0 days |
| bcrypt cost 10 | 73 ms/check | 261.4 days |
| bcrypt cost 12 | 266 ms/check | 2.6 years |

## How to read this

- The fast hashes run through the simulator's own engine, which is single-threaded pure Python. Dedicated tools such as Hashcat on a GPU are many orders of magnitude faster, so these rows are a floor for an attacker, not a ceiling.
- bcrypt's cost is encoded in the hash (`$2b$12$...` is cost 12). Each +1 doubles the work. OWASP asks for a work factor of at least 10 and ranks bcrypt as a legacy choice behind Argon2id and scrypt.
- The last column is the full search time for one hash. The simulator refuses that work: brute force and mask runs stop at a 26^6 search-space cap, and bcrypt runs stop after 500 attempts or 30 s.
- A slow hash does not save a weak password. A dictionary attack against bcrypt still finds `qwerty` on the fourth guess; only the time per guess changes.
