#!/usr/bin/env bash
set -euo pipefail

# Wrapper for running SP1 GPU proofs locally. SP1's CudaProver connects to a
# local sp1-gpu-server process over a Unix socket (not a remote HTTP server).
# The server takes several seconds to initialize, but the Rust client's auto-start
# retry window is short, so we start it explicitly, wait for its socket, run the
# client, and then stop the server.

CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"
DEVICE_ID="${CUDA_VISIBLE_DEVICES%%,*}"
export CUDA_VISIBLE_DEVICES

SOCKET="/tmp/sp1-cuda-${DEVICE_ID}.sock"
SERVER_BIN="${HOME}/.sp1/bin/sp1-gpu-server"

# Clean up any stale socket.
rm -f "$SOCKET"

# Start the server in the background.
"$SERVER_BIN" > /tmp/sp1-gpu-server.log 2>&1 &
SERVER_PID=$!

# Wait for the socket to appear (up to 30s).
for _ in $(seq 1 300); do
    if [ -S "$SOCKET" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S "$SOCKET" ]; then
    echo "sp1-gpu-server failed to start" >&2
    cat /tmp/sp1-gpu-server.log >&2 || true
    exit 1
fi

# Run the local CUDA client.
set +e
./target/release/prove-sp1 --gpu --device-id "$DEVICE_ID" "$@"
STATUS=$?
set -e

# Stop the server.
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
rm -f "$SOCKET"

exit "$STATUS"
