#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/compare-openvm-ceno-4090.sh [--setup] [--skip-openvm] [--skip-ceno]

Runs a fair Scroll OpenVM vs Ceno proof-time comparison on a 4090-class GPU.

Options:
  --setup        Run one-time checks and guest builds before benchmarking.
  --skip-openvm  Do not run OpenVM.
  --skip-ceno    Do not run Ceno.
  -h, --help    Show this help.

The reported metric is setup-excluded e2e create_proof time:
  chunk create_proof + batch create_proof + bundle/root create_proof.

Outputs are written under .output/ceno-openvm-4090-<timestamp>/.
USAGE
}

RUN_SETUP=0
RUN_OPENVM=1
RUN_CENO=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup)
      RUN_SETUP=1
      shift
      ;;
    --skip-openvm)
      RUN_OPENVM=0
      shift
      ;;
    --skip-ceno)
      RUN_CENO=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${RUN_OPENVM}" == "0" && "${RUN_CENO}" == "0" ]]; then
  echo "nothing to run: both OpenVM and Ceno are skipped" >&2
  exit 2
fi

if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "nvidia-smi not found; this script is intended for a GPU server" >&2
  exit 1
fi

if ! nvidia-smi -L | grep -q .; then
  echo "no NVIDIA GPU detected by nvidia-smi" >&2
  exit 1
fi

TS="$(date -u +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-.output/ceno-openvm-4090-${TS}}"
mkdir -p "$OUT_DIR"

export GPU=1
export CENO_MAX_CELL_PER_SHARD="${CENO_MAX_CELL_PER_SHARD:-1245708288}"
export RUST_LOG="${RUST_LOG:-scroll_zkvm_prover=info,scroll_zkvm_integration=debug}"

echo "[bench] output dir: $OUT_DIR"
echo "[bench] CENO_MAX_CELL_PER_SHARD=$CENO_MAX_CELL_PER_SHARD"
echo "[bench] GPU inventory:"
nvidia-smi -L | tee "$OUT_DIR/gpu.txt"

if [[ "$RUN_SETUP" == "1" ]]; then
  echo "[setup] cargo check --workspace"
  cargo check --workspace 2>&1 | tee "$OUT_DIR/setup-root-cargo-check.log"

  echo "[setup] cd ceno && cargo check --workspace --all-targets"
  (
    cd ceno
    cargo check --workspace --all-targets
  ) 2>&1 | tee "$OUT_DIR/setup-ceno-cargo-check.log"

  echo "[setup] build OpenVM guests"
  cargo run --release -p scroll-zkvm-build-guest -- --mode force \
    2>&1 | tee "$OUT_DIR/setup-build-guest-openvm.log"

  echo "[setup] build Ceno guests/prover"
  make build-guest-ceno 2>&1 | tee "$OUT_DIR/setup-build-guest-ceno.log"
else
  echo "[setup] skipped; pass --setup for one-time checks and guest builds"
fi

clear_outputs() {
  rm -rf .output/bundle-tests-* .output/batch-tests-* .output/chunk-tests-*
  rm -rf ceno/releases/dev/ceno/prover-test
}

run_ceno() {
  echo "[ceno] clearing cached proof outputs"
  clear_outputs

  echo "[ceno] chunk"
  GPU=1 CENO_MAX_CELL_PER_SHARD="$CENO_MAX_CELL_PER_SHARD" \
    make test-e2e-ceno-chunk 2>&1 | tee "$OUT_DIR/ceno-chunk.log"

  echo "[ceno] batch"
  GPU=1 CENO_MAX_CELL_PER_SHARD="$CENO_MAX_CELL_PER_SHARD" \
    make test-e2e-ceno-batch 2>&1 | tee "$OUT_DIR/ceno-batch.log"

  echo "[ceno] bundle"
  GPU=1 CENO_MAX_CELL_PER_SHARD="$CENO_MAX_CELL_PER_SHARD" \
    make test-e2e-ceno-bundle 2>&1 | tee "$OUT_DIR/ceno-bundle.log"
}

run_openvm() {
  echo "[openvm] clearing cached proof outputs"
  clear_outputs

  echo "[openvm] bundle e2e; this builds chunk, batch, and bundle/root proofs"
  GPU=1 RUST_LOG="$RUST_LOG" \
    make test-e2e-bundle 2>&1 | tee "$OUT_DIR/openvm-bundle.log"
}

if [[ "$RUN_CENO" == "1" ]]; then
  run_ceno
fi

if [[ "$RUN_OPENVM" == "1" ]]; then
  run_openvm
fi

python3 - "$OUT_DIR" "$RUN_CENO" "$RUN_OPENVM" <<'PY'
import pathlib
import re
import sys

out_dir = pathlib.Path(sys.argv[1])
run_ceno = sys.argv[2] == "1"
run_openvm = sys.argv[3] == "1"

lines = []
lines.append("# OpenVM vs Ceno 4090 Comparison")
lines.append("")
lines.append("Metric: setup-excluded e2e create_proof time.")
lines.append("")

if run_ceno:
    ceno_paths = [
        pathlib.Path("ceno/releases/dev/ceno/prover-test/chunk/proving_time_ms.txt"),
        pathlib.Path("ceno/releases/dev/ceno/prover-test/batch/proving_time_ms.txt"),
        pathlib.Path("ceno/releases/dev/ceno/prover-test/bundle/proving_time_ms.txt"),
    ]
    ceno_labels = ["chunk", "batch", "bundle/root"]
    ceno_values = []
    lines.append("## Ceno")
    for label, path in zip(ceno_labels, ceno_paths):
        if not path.exists():
            raise SystemExit(f"missing Ceno timing file: {path}")
        value = int(path.read_text().strip())
        ceno_values.append(value)
        lines.append(f"- {label}: {value} ms")
    lines.append(f"- total: {sum(ceno_values)} ms")
    lines.append("")

if run_openvm:
    log_path = out_dir / "openvm-bundle.log"
    if not log_path.exists():
        raise SystemExit(f"missing OpenVM log: {log_path}")
    text = log_path.read_text(errors="replace")

    stark_ms = []
    stark_lines = []
    for line in text.splitlines():
        if "proving speed:" not in line or "time:" not in line:
            continue
        match = re.search(r"time:\s*([0-9]+(?:\.[0-9]+)?)s", line)
        if match:
            value = round(float(match.group(1)) * 1000)
            stark_ms.append(value)
            stark_lines.append((value, line.strip()))

    evm_ms = []
    evm_lines = []
    for line in text.splitlines():
        match = re.search(
            r"openvm\s+(.+?)\s+evm create_proof time \(setup excluded\):\s*([0-9]+)ms",
            line,
        )
        if match:
            value = int(match.group(2))
            evm_ms.append(value)
            evm_lines.append((value, line.strip()))

    lines.append("## OpenVM")
    if not stark_ms:
        lines.append("- warning: no OpenVM STARK proving-speed lines found")
    else:
        lines.append(f"- STARK proof subtotal: {sum(stark_ms)} ms")
        for idx, (value, raw) in enumerate(stark_lines, 1):
            lines.append(f"  - stark #{idx}: {value} ms | {raw}")

    if not evm_ms:
        lines.append("- warning: no OpenVM EVM/root create_proof timing line found")
        lines.append("  Rebuild after the OpenVM timing patch before using this as a fair root-inclusive comparison.")
    else:
        lines.append(f"- EVM/root proof subtotal: {sum(evm_ms)} ms")
        for idx, (value, raw) in enumerate(evm_lines, 1):
            lines.append(f"  - evm/root #{idx}: {value} ms | {raw}")

    lines.append(f"- total: {sum(stark_ms) + sum(evm_ms)} ms")
    lines.append("")

summary = "\n".join(lines)
(out_dir / "summary.md").write_text(summary + "\n")
print(summary)
print(f"\n[bench] wrote {out_dir / 'summary.md'}")
PY
