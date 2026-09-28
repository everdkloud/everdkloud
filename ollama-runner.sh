#!/bin/bash
set -euo pipefail

BASE="${OLLAMA_HOME:-/var/lib/eversmartnode/ollama}"
BIN="${EVERSMARTNODE_OLLAMA_BIN:-$BASE/current/bin/ollama}"
mkdir -p "$BASE" "${OLLAMA_MODELS:-$BASE/models}"

# Ollama is intentionally NOT baked into the Docker image. Keep this Supervisor
# program alive and idle until the head admin installs Ollama from the AI tab.
while [ ! -x "$BIN" ]; do
  sleep 5
done

exec "$BIN" serve
