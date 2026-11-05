#!/usr/bin/env bash
# Starts the BCPS chatroom server (Linux, ChromeOS Linux/Crostini, Codespaces, macOS).
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.10+ is required. On ChromeOS Linux or Debian/Ubuntu run: sudo apt install python3"
  exit 1
fi
[ -f .env ] || cp .env.example .env
echo "Starting BCPS chatroom on http://127.0.0.1:3000 (owner claim code prints below on first run)"
exec python3 backend/server.py
