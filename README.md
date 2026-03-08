# BRUTE.EXE — A Password Attack Simulator

An industrial-grade, real-time password attack simulation dashboard. This educational cybersecurity application safely imitates password attack techniques against user-provided sample passwords to demonstrate password vulnerability, estimate password strength, visualize attack behavior, and provide practical security recommendations. Built with a FastAPI (Python) backend and a React (TypeScript) frontend.

## Architecture Overview

The system follows a producer-consumer model over WebSockets:
- **Backend (Python/FastAPI)**: 
  - Asynchronous simulation engine using logical generators (`simulator.py`).
  - Resource protection via concurrent connection limits and input validation (`main.py`).
  - Real-time performance metrics (Guesses/Sec, Entropy analysis).
- **Frontend (React/TS)**: 
  - Reactive dashboard styled with a custom **"Industrial Signal"** CSS theme (manual CSS, no framework).
  - Persistence-aware state management (retains last attack data).
  - Custom UI components: `TimerRings` (dual-ring chrono timer), `AttackTicks` (animated hash-flow indicator), `CipherStrength` (segmented bit-bar).

## Design System — "Industrial Signal"

The UI uses a custom, hand-crafted CSS architecture (`App.css`, `index.css`) with no CSS framework dependencies:

| Token       | Value       | Usage                          |
|-------------|-------------|--------------------------------|
| `--bg`      | `#171c1c`   | Deep teal background           |
| `--fg`      | `#d1e0c2`   | Pale sage green text & accents |
| `--border`  | `#2a3331`   | Subtle grid borders            |
| `--accent`  | `#d1e0c2`   | Interactive element highlights |

### Dashboard Layout
- **3-column grid** (`.fui-dashboard-grid`) with 6 functional slots:
  1. **Cipher Strength** — Bit-level complexity indicator with segmented bars.
  2. **Vector Status** — Animated tick-based hash-flow visualization.
  3. **Chrono-Vector** — Dual-ring timer (inner: seconds, outer: minutes).
  4. **Cracking Speed** — Real-time throughput in Guesses/Second.
  5. **Transfer Details** — Current guess and total cycle count.
  6. **Actions** — Input, attack initiation, and cancel controls.

### Key UI Features
- **Completion Modal**: Full-screen overlay displaying cracked password and performance metrics.
- **Animated Indicators**: Rotating tick rings, pulsing status labels, and smooth CSS transitions.
- **Educational Disclaimer**: Prominently displayed at the bottom with a flashing ⚠ warning badge.

## Security Features
- **Concurrent Connection Limiting**: Prevents CPU exhaustion by limiting to 5 active simulations.
- **Input Sanitization**: Client and server-side password length validation (max 64 chars).
- **Restricted CORS**: Backend only accepts requests from trusted local dev origins.

## Documentation
The codebase follows industry-standard documentation practices:
- **Python**: Google Style Docstrings for modules and classes.
- **TypeScript**: TSDoc for components and state interfaces.
- **CSS**: Modular documentation for design tokens and layout logic.

## Getting Started

### Prerequisites
- Python 3.8+
- Node.js 18+

### Backend Setup
1. `pip install fastapi uvicorn websockets`
2. `npm run dev:server` — Starts the FastAPI backend on port **8000**.

### Frontend Setup
1. `npm install`
2. `npm run dev` — Starts the Vite dev server on port **5173**.

### Running Both
Open two terminals and run both commands simultaneously. The frontend at `localhost:5173` will connect to the backend at `localhost:8000` via WebSocket.

## Testing and Verification
- Run automated security tests: `pytest test_security.py`
- Manual security check: `py verify_security.py run`
- Backend connectivity test: `py test_backend.py`

---
*⚠ Disclaimer: BRUTE.EXE is for educational purposes only. It is designed to demonstrate cybersecurity concepts and password vulnerability. It should never be used for malicious activities.*
