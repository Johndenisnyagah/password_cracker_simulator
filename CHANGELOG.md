# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- bcrypt verifications now run in a worker thread, so a slow bcrypt job no
  longer freezes the server. Previously a cost-12 brute force held the asyncio
  event loop long enough that `/health` took ~134 s to answer.
- The WebSocket endpoint checks the `Origin` header against `CORS_ORIGINS`
  before accepting a handshake, closing a cross-site WebSocket hijacking hole
  ([CWE-1385](https://cwe.mitre.org/data/definitions/1385.html)). CORS
  middleware never covered WebSockets.

### Added
- Argon2id and PBKDF2-HMAC-SHA256 as supported algorithms, both cracked via
  the same slow-KDF path as bcrypt (shared attempt/time cap).
- `POST /audit`: grades a pasted hash against the OWASP Password Storage Cheat
  Sheet (algorithm ranking, bcrypt cost, Argon2id memory/time, PBKDF2
  iterations) without needing the plaintext. New `storage_audit.py` module.
- Every bcrypt run (brute force, dictionary, mask) stops after 500 attempts or
  30 seconds, whichever comes first. Mask and dictionary runs were previously
  uncapped against bcrypt.
- `scripts/benchmark.py` measures real cracking speeds per algorithm and writes
  `docs/benchmark-results.md`; CI runs a smoke pass.
- Dependabot (pip, npm, GitHub Actions, Docker), `SECURITY.md`, and this
  changelog.
- Dockerfile now runs as a non-root user and reports container health.

### Changed
- bcrypt time estimates read the cost factor from the hash and time one real
  check instead of assuming ~50 ms.
- Python pinned to 3.12 across the Dockerfile, Render, and CI.
- Replaced `print()` with stdlib `logging`; dropped the private
  `Semaphore._value` access in favour of a public active-connection counter.
- Removed the leftover `verify_security.py` stub and Tauri template assets.
