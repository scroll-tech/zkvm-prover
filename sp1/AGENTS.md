# SP1 zkVM Backend — Agent Notes

This directory is a self-contained Cargo workspace that prototypes SP1 as a second zkVM backend for scroll-zkvm-prover.

## Quick commands

```bash
# Build all SP1 guest ELFs and the prove-sp1 host binary
make build-guest-sp1

# Run GPU end-to-end tests (requires NVIDIA GPU and ~/.sp1/bin/sp1-gpu-server)
CUDA_VISIBLE_DEVICES=3 make test-e2e-sp1-chunk
CUDA_VISIBLE_DEVICES=3 make test-e2e-sp1-batch
CUDA_VISIBLE_DEVICES=3 make test-e2e-sp1-bundle
```

## Workspace layout

- `circuits/{chunk,batch,bundle}-circuit/` — SP1 guest programs (RISC-V ELFs).
- `build-guest/` — host binary that compiles the guest ELFs to `releases/dev/sp1/{chunk,batch,bundle}/app`.
- `prover-test/` — host binary `prove-sp1` that loads an ELF and generates core/compressed/Plonk proofs.
- `run-gpu-prover.sh` — wrapper that manages the local `sp1-gpu-server` lifecycle. The server runs on the same machine and talks to the SP1 SDK over a Unix socket (this is SP1's "local" GPU mode, not the remote HTTP network prover).
- `types/` — minimal shared types used by the SP1 guest crates.

## SP1 prerequisites

- `sp1up` installed; `~/.sp1/bin/sp1-gpu-server` and `cargo-prove` present.
- Plonk circuit artifacts extracted:
  ```bash
  cd ~/.sp1/circuits/plonk/v6.1.0
  tar -xzf artifacts.tar.gz
  ```
  The GPU server will panic with `plonk_circuit.bin: no such file or directory` otherwise.

## Current status

- `chunk` circuit executes real Scroll chunk logic: it deserializes a `ChunkWitness`, runs `ChunkInfo::try_from`, and commits the chunk `pi_hash`.
- `batch` circuit performs real recursive aggregation: it verifies the compressed SP1 proofs of the child chunks, validates the batch payload against the chunk infos, verifies the EIP-4844 blob KZG proof in-circuit, derives `BatchInfo`, and commits the batch `pi_hash`.
- `bundle` circuit performs real recursive aggregation: it verifies the compressed SP1 proof of the child batch, derives `BundleInfo`, and commits the bundle `pi_hash`.
- `make test-e2e-sp1-bundle` also runs the Solidity verifier test in `sp1/verifier/`.

## Known limitations

- The SP1 workspace is isolated from the main workspace because SP1 and OpenVM pull incompatible revm/alloy versions.
- `crates/types/sp1/` in the main workspace is a placeholder abstraction crate; full type sharing between OpenVM and SP1 backends is future work.

## Version sensitivity

All SP1 workspace crates must use the **exact same** SP1 SDK / guest version. Mismatched versions between `sp1-sdk`, `sp1-zkvm`, `sp1-build`, `sp1-hypercube`, `sp1-primitives`, and the `sp1-gpu-server` binary can produce incompatible proof artifacts, VK formats, or verifier contracts. After any SP1 version bump, rebuild guest ELFs with `make build-guest-sp1`.
