# BRUTE.EXE - Educational Password Cracking Simulator

> An educational hash-cracking dashboard built to demonstrate how MD5, SHA-1, SHA-256, and bcrypt fare against brute-force, dictionary, and mask-based attacks - and why bcrypt wins.

[![CI](https://github.com/Johndenisnyagah/password_cracker_simulator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Johndenisnyagah/password_cracker_simulator/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-async-009688)
![React](https://img.shields.io/badge/React-19-61dafb)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6)
![Tests](https://img.shields.io/badge/tests-28%20passing-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

> **Educational use only.** This tool only ever cracks hashes that you paste into it. It never sends data anywhere, never targets remote systems, and is not a real attacker\'s tool. See [Security & ethics](#security--ethics).

---

## Demo

<!-- TODO: record GIF -->
![Dashboard demo](docs/demo.gif)

<!-- TODO: add a static screenshot -->
![Dashboard screenshot](docs/screenshot.png)

**Try it live:** _(deploy the `password-cracker-backend` service from `render.yaml` and update this link)_

---

## What this project demonstrates

This is a portfolio project intended to show:

- **Realistic threat modelling** - the three industry-standard offline attack strategies (brute force, dictionary, mask) against the four most common hash algorithms.
- **Async Python** - FastAPI + WebSockets streaming progress events from an async generator-based cracker engine.
- **Defensive engineering** - Pydantic request validation, env-driven CORS allowlist, asyncio.Semaphore for connection limits, search-space safety caps, structured error responses.
- **Why bcrypt matters** - the same dictionary attack that cracks a SHA-256 hash in microseconds takes orders of magnitude longer against bcrypt; a brute force against bcrypt is refused outright with a years-to-finish estimate.

---

## Tech stack

| Layer | Stack |
|---|---|
| Backend | Python 3.10+, FastAPI, Pydantic v2, Uvicorn, asyncio |
| Crypto | hashlib (md5/sha1/sha256), bcrypt |
| Frontend | React 19, TypeScript 5, Vite 7 |
| Tests | pytest, pytest-asyncio, websockets (client) |
| Deploy | Docker, Render (backend), Vercel/Netlify (frontend) |

---

## Attack modes

The backend exposes one WebSocket endpoint - `ws://<host>/ws/simulate` - that accepts an `AttackRequest` payload and streams `starting` -> `running` -> `complete` / `exhausted` / `error` updates.

### 1. Brute force

Iterates every candidate over a charset up to `max_length`. Search space is checked against a hard safety cap (`26^6 = 308,915,776`) before iteration starts.

```json
{
  "hash": "187ef4436122d1cc2f40dc2b92f0eba0",
  "algorithm": "md5",
  "attack_mode": "brute_force",
  "charset": "alphanumeric",
  "max_length": 3
}
```

Supported charsets: `lower`, `upper`, `digits`, `alphanumeric`, `all`.

### 2. Dictionary

Tries entries from the bundled `wordlist.txt` (~166 common passwords). Wins almost instantly against the kind of passwords found in real breach corpora.

```json
{
  "hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "algorithm": "sha256",
  "attack_mode": "dictionary"
}
```

### 3. Mask (Hashcat-style)

Constrains the search to a known pattern. Useful for passwords with predictable structure (e.g. `username + ?d?d`).

Tokens: `?l` (lower), `?u` (upper), `?d` (digits), `?s` (special), `?a` (all). Literal characters are kept as-is.

```json
{
  "hash": "5e75a4e07ac1d2956ae9211e0b1a5bdf2c79c8c8",
  "algorithm": "sha1",
  "attack_mode": "mask",
  "mask": "?l?l?d?d"
}
```

---

## The bcrypt moment

bcrypt is intentionally slow (~50ms per hash, by design). The simulator surfaces this concretely:

- **Dictionary attack against bcrypt:** cracks `qwerty` in 4 attempts (~6 ms) - because the wordlist itself is short. This shows bcrypt does **not** protect against weak passwords.
- **Brute force against bcrypt:** the cracker refuses to spin for years. It emits a warning like *"bcrypt is intentionally slow. Brute-forcing this space would take roughly 0.5 years at ~50ms/check"* and caps attempts at 500.

This is the educational payoff: bcrypt buys you time against brute force, but a weak password is still a weak password.

---

## Setup

### Prerequisites

- Python 3.10+
- Node.js 18+

### Backend

```bash
pip install -r requirements.txt
python main.py
# or: uvicorn main:app --host 0.0.0.0 --port 8000
```

The backend listens on `:8000` by default. Visit `http://localhost:8000/health` to confirm it is up.

### Frontend

```bash
npm install
npm run dev
```

Vite serves the dashboard at `http://localhost:5173`. The frontend connects to the backend at `VITE_BACKEND_WS_URL` (defaults to `ws://localhost:8000`) - set it in `.env.local` for non-local deploys.

### Docker

```bash
docker build -t brute-exe .
docker run -p 8000:8000 -e CORS_ORIGINS=http://localhost:5173 brute-exe
```

### Render (backend)

The included `render.yaml` deploys the FastAPI backend as a free-tier web service. Pair it with Vercel or Netlify for the frontend.

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated allowlist of origins. Set this to your deployed frontend URL in production. |
| `PORT` | `8000` | Render injects this automatically. |

---

## Testing

```bash
pytest -v
```

The suite covers:

- **`test_simulator.py`** (18 tests) - hash verification across md5/sha1/sha256/bcrypt, brute-force happy + exhausted + oversize cases, dictionary happy + exhausted + bundled-wordlist cases, mask parser (4 cases) and mask attack happy + oversize cases.
- **`test_security.py`** (5 tests, end-to-end via a live uvicorn server) - invalid payload rejection, invalid JSON, unsupported algorithm, search-space cap, end-to-end happy path.

**Current status:** 23/23 passing in under a second.

---

## Architecture

```
+----------------+   WebSocket    +---------------------+
|  React UI      | <------------> |  FastAPI endpoint   |
|  (Vite/TS)     |  JSON stream   |  /ws/simulate       |
+----------------+                +----------+----------+
                                             |
                                             v
                                  +----------+----------+
                                  |  HashCracker        |
                                  |  - brute_force()    |
                                  |  - dictionary()     |
                                  |  - mask()           |
                                  +----------+----------+
                                             |
                                             v
                                  +----------+----------+
                                  |  hashlib / bcrypt   |
                                  +---------------------+
```

The cracker is an async generator. Each iteration yields a JSON-serialisable progress dict, the endpoint forwards it over the WebSocket, and the React dashboard merges it into its `stats` state.

---

## Security & ethics

This is a teaching tool. It hashes guesses locally and compares them to a hash you paste into the UI. It does not - and cannot - target remote systems.

**Do not use this (or any cracking tool) against systems you do not own or have written permission to test.** Unauthorised computer access is illegal in most jurisdictions (US: CFAA, UK: Computer Misuse Act, EU: NIS 2 / national law).

If you are interested in this space:
- Try the [Hack The Box Academy](https://academy.hackthebox.com/) password-cracking modules.
- Read [OWASP\'s password storage cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- For real research on offline cracking, use [Hashcat](https://hashcat.net/) or [John the Ripper](https://www.openwall.com/john/) - both far faster than anything this educational simulator does.

---

## Roadmap

Things on my list for future iterations:

- [ ] CI pipeline (GitHub Actions: ruff, mypy, pytest, docker build).
- [ ] Hardened Dockerfile (non-root user, HEALTHCHECK, multi-stage build).
- [ ] Logging via stdlib `logging` instead of `print()`.
- [ ] Plug-in larger wordlists (rockyou-style) without bundlin