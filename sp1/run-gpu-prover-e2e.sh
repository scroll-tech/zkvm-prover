#!/usr/bin/env bash
set -euo pipefail

# Full SP1 chunk -> batch -> bundle e2e on a single GPU.
# Delegates each circuit to run-gpu-prover.sh, which starts/stops the local
# sp1-gpu-server for that circuit. The SP1 CudaProver client tears down the
# server when a proof session ends, so we cannot keep one server alive across
# all three circuits.

CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"
DEVICE_ID="${CUDA_VISIBLE_DEVICES%%,*}"
export CUDA_VISIBLE_DEVICES

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for circuit in chunk batch bundle; do
    echo "========================================"
    echo " proving circuit: $circuit"
    echo "========================================"
    "${SCRIPT_DIR}/run-gpu-prover.sh" --circuit "$circuit"
done

echo "========================================"
echo " SP1 chunk->batch->bundle e2e complete"
echo "========================================"
