# AGENTS.md - Ceno backend

This directory is an isolated Ceno Cargo workspace. Keep Ceno dependencies and patches here;
do not add Ceno crates to the root OpenVM workspace.

The workspace uses the local Ceno checkout at `../../ceno` and the local GPU HAL at
`../../ceno-gpu/cuda_hal`, matching the Ceno branch used by `../../ceno-reth-benchmark`.

Build and validation commands:

```bash
cd ceno && cargo check --workspace --all-targets
make build-guest-ceno
GPU=1 make test-e2e-ceno-chunk
GPU=1 make test-e2e-ceno-batch
GPU=1 make test-e2e-ceno-bundle
```

`GPU=1` is required for E2E proof commands. CPU fallback is intentionally rejected so the
commands fail loudly when GPU proving is unavailable.

Artifact layout:

- `ceno/releases/dev/ceno/{chunk,batch,bundle}/app` - compiled Ceno guest ELFs.
- `ceno/releases/dev/ceno/prover-test/<circuit>/` - hints, app proofs, root proof,
  verifying-key metadata, and public-output digests.
