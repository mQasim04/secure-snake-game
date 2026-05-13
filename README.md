# 🔐 Secure Snake Game

A Snake game built as an **Information Security** project. Every login, save, and score is protected by real cryptography — all running in the browser with no backend.

## Security Features

- **SHA-256** — salted password hashing, never stored in plain text
- **AES-256-GCM** — save file encryption
- **RSA-2048** — AES key wrapping
- **PBKDF2** — RSA private key protection
- **SHA-256 integrity check** — detects save file tampering
- **Session timeout** — auto-logout after 10 minutes
- **Rate limiting** — blocks brute-force login attempts

All crypto is handled by the browser's built-in **Web Crypto API**. Data is stored encrypted in `localStorage` — nothing is sent to any server.

## Run Locally

Just open `Game.html` in any modern browser. No installation needed.

## Tech

HTML · CSS · JavaScript · Web Crypto API

## Author

**Muhammad Qasim** — [LinkedIn](https://linkedin.com/in/muhammad-qasim-b14a26325/)
