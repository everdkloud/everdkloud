#!/bin/bash
set -euo pipefail

BASE="${OLLAMA_HOME:-/var/lib/eversmartnode/ollama}"
INSTALLS="$BASE/installs"
CURRENT="$BASE/current"
LOCK="$BASE/.install-lock"
LOG="$BASE/install.log"
DEST=""
SUCCESS=0

mkdir -p "$BASE" "$INSTALLS" "$BASE/models"

if ! mkdir "$LOCK" 2>/dev/null; then
  echo "Ollama installation is already running on this instance." >&2
  exit 75
fi
cleanup(){
  rc=$?
  if [ "$SUCCESS" -ne 1 ] && [ -n "$DEST" ]; then rm -rf "$DEST" 2>/dev/null || true; fi
  rmdir "$LOCK" 2>/dev/null || true
  trap - EXIT
  exit "$rc"
}
trap cleanup EXIT

exec >>"$LOG" 2>&1

echo "[$(date -u +%FT%TZ)] Ollama on-demand installation started."

if ! command -v zstd >/dev/null 2>&1; then
  echo "zstd is required but is not available in this image." >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required but is not available in this image." >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DEST="$INSTALLS/$STAMP"
URL="https://ollama.com/download/ollama-linux-${ARCH}.tar.zst"
mkdir -p "$DEST"

echo "Downloading and extracting official Ollama Linux ${ARCH} package..."
# Stream directly into extraction so the instance does not need space for both
# a multi-GB compressed archive and the extracted runtime at the same time.
curl --fail --show-error --location --retry 3 --retry-delay 2 "$URL" \
  | zstd -dc \
  | tar -xf - -C "$DEST"

test -x "$DEST/bin/ollama"
"$DEST/bin/ollama" --version || true

LINK_TMP="$BASE/.current-$STAMP"
ln -s "$DEST" "$LINK_TMP"
mv -Tf "$LINK_TMP" "$CURRENT"

# Keep the current runtime and at most one previous runtime. The previous copy
# gives us a rollback target if a future update is interrupted or bad.
CURRENT_REAL="$(readlink -f "$CURRENT" 2>/dev/null || true)"
mapfile -t OLD < <(find "$INSTALLS" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | awk '{print $2}')
KEPT=0
for d in "${OLD[@]:-}"; do
  [ -n "$d" ] || continue
  if [ "$(readlink -f "$d")" = "$CURRENT_REAL" ]; then continue; fi
  KEPT=$((KEPT+1))
  if [ "$KEPT" -gt 1 ]; then rm -rf "$d"; fi
done

SUCCESS=1
echo "[$(date -u +%FT%TZ)] Ollama installed at $CURRENT_REAL"
echo "The Supervisor runner will start/restart Ollama on 127.0.0.1:11434."
