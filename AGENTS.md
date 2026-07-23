# AGENTS.md — scroll-zkvm-prover

Critical context for AI agents working on this repo. Read this before making changes, especially around OpenVM upgrades or guest builds.

## Project Structure

- **Guest circuits**: `crates/circuits/{chunk,batch,bundle}-circuit/` — RISC-V ELFs compiled to `.vmexe`
- **Build tool**: `crates/build-guest/` — generates guest assets, commitments, verifier contract
- **Host prover**: `crates/prover/` — loads guest executables and runs STARK/SNARK proving
- **Integration tests**: `crates/integration/` — end-to-end tests (chunk → batch → bundle)
- **Asset outputs**: `releases/dev/{chunk,batch,bundle,verifier}/`
- **Test outputs**: `.output/` — cached proofs and intermediate artifacts

## OpenVM Version Sensitivity

This project uses **OpenVM v2.0.0** as its ZKVM. Guest executables (`.vmexe`) and host code **must be built from the exact same OpenVM version**. Even a minor version bump can change:

- The guest/host data layout (hint streams, public inputs)
- The Halo2 SRS degree requirement
- The EVM verifier contract ABI
- Field algebra APIs
- ECC constructor signatures

### How to update OpenVM dependencies correctly

OpenVM is declared as a **git dependency** (`tag = "v2.0.0"`) in `Cargo.toml`, and the exact commit is also pinned in `Cargo.lock`. The `openvm-org/openvm.git` and `openvm-org/stark-backend.git` entries MUST stay on matching tags — `openvm`'s own `Cargo.toml` pins a specific `stark-backend` tag, and a mismatch produces duplicate-registry / type-mismatch errors. Because the tag is immutable, the declared ref and the locked commit should always agree. The real hazard is a bare `cargo update`: it will **not** change the OpenVM tag, but it will bump unrelated crates.io packages (e.g. `alloy`, `revm`) which often break compatibility with the `scroll-tech/reth` and `sbv` forks.

**Do NOT run a global `cargo update` unless you are prepared to upgrade the entire `alloy`/`revm`/`reth`/`sbv` dependency chain together.**

To move to a newer OpenVM tag, retarget every `openvm-org/openvm.git` and `openvm-org/stark-backend.git` entry in `Cargo.toml` to the new tag, then refresh only those git sources — `cargo metadata` is enough — rather than a global `cargo update`. Verify with `git diff Cargo.lock` that no other package's version/source changed. Then rebuild guests and run tests as described below.

### After ANY OpenVM version upgrade, you MUST:

1. **Update the hardcoded version string** in `crates/build-guest/src/verifier.rs`:
   ```rust
   let solidity_sdk_tag = "v2.0"; // MUST match openvm-solidity-sdk tag
   let verifier_path = "v2.0-deferral"; // bundle/deferral verifier
   ```

2. **Force-rebuild ALL guest assets** (auto mode skips existing files):
   ```bash
   # Local build
   OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 cargo run --release -p scroll-zkvm-build-guest -- --mode force

   # Docker build (matches CI)
   OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 make build-guest
   ```
   This regenerates: `app.elf`, `app.vmexe`, commitment `.rs` files, `agg_vk.bin`, `openVmVk.json`,
   and the EVM verifier (`verifier.sol` + `verifier.bin`).

   > The default `RECOMPUTE_MODE=auto` tries to download the Solidity verifier from
   > `openvm-solidity-sdk` and compiles it locally with `solc` to produce `verifier.bin`.
   > If the download fails, it falls back to the full local OpenVM verifier generation.
   > `RECOMPUTE_MODE=yes` skips the download and always generates the verifier locally;
   > `RECOMPUTE_MODE=no` forces download-only and fails if no pre-built verifier is available.

   > Building `batch` or `bundle` requires the SDK of the previous circuit
   > (`batch` needs `chunk`, `bundle` needs `batch`). Always build in a single
   > `force` run so dependencies are generated in the correct order.

3. **Verify commitments were updated** — check that `*_exe_commit.rs` and `*_vm_commit.rs` files changed, and that `openVmVk.json` timestamps are fresh.

4. **Clear global OpenVM caches** in `~/.openvm/`:
   ```bash
   rm -f ~/.openvm/agg_stark.pk ~/.openvm/agg_stark.vk ~/.openvm/root.asm
   ```
   These are cached proving keys. They are **not** automatically invalidated on version bumps.

5. **Check SRS params** in `~/.openvm/params/`:
   - OpenVM v2.0.0 requires `kzg_bn254_24.srs` (2 GB); the SNARK step in e2e tests also needs `kzg_bn254_22.srs` and `kzg_bn254_23.srs`
   - Download any missing file with `make $HOME/.openvm/params/<name>.srs`
   - If a file is empty/corrupted, replace it (check for `.1` or `.part` suffixes from interrupted downloads)

6. **Clear test output cache** before re-running integration tests:
   ```bash
   rm -rf .output/bundle-tests-*/
   ```
   Integration tests reuse cached proofs by default. Stale proofs from a previous OpenVM version will cause failures.

## Common Failure Patterns

### `NativeHintSliceSubEx` assertion failure
```
assertion left == right failed (left: 21, right: 1)
```
**Cause**: Stale guest assets (`app.vmexe`) from a previous OpenVM version.  
**Fix**: Follow all 6 steps above.

### `UnexpectedEof` in `CacheHalo2ParamsReader::read_params`
```
UnexpectedEof: failed to fill whole buffer
```
**Cause**: `~/.openvm/params/kzg_bn254_24.srs` is missing, empty, or truncated.  
**Fix**: Ensure a valid 2 GB SRS file exists at that exact path.

### `ProofVerificationFailed()` (Solidity error `0xd611c318`)
**Cause**: The EVM verifier was generated with a different circuit config than the proof.
This happens when:
- The verifier was built with `RECOMPUTE_MODE=no` but the downloaded verifier is missing, stale, or has empty bytecode
- The verifier was built **without** the deferral prover, but the proof uses deferral (batch/bundle)
- The verifier's `AggregationTreeConfig` does not match the prover's (`num_children_internal/leaf`)

**Fix**: Regenerate with:
```bash
OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 cargo run --release -p scroll-zkvm-build-guest -- --mode force
```
(The default `auto` mode will fall back to local generation if the download fails; use `RECOMPUTE_MODE=yes` to force local generation immediately.)

### `cargo update` breaks compilation with alloy/revm type mismatches
**Symptoms**: Errors like `missing verify_and_compute_signer_unchecked in implementation` (alloy) or `mismatched types` between `revm_primitives::hardfork::SpecId` and `SpecId` (revm).
**Cause**: A global `cargo update` bumps `alloy` to 1.8.x and `revm` to 30.2.0, but the `scroll-tech/reth` and `sbv` forks were built against older versions. The `[patch.crates-io]` table pins `revm` to `scroll-v91` (30.1.1), which no longer satisfies the newer `alloy-evm` requirements, leading to duplicate registry versions of `revm-handler` / `revm-primitives` in the dependency graph.
**Fix**: Restore the original `Cargo.lock` (`git checkout HEAD -- Cargo.lock`) and update only what you actually need (e.g. `cargo metadata` scoped to the OpenVM git sources).

### Docker build fails with stale CID
The `build-guest.sh` script may fail if a stale `build-guest.cid` file exists. Use local build (`cargo run -p scroll-zkvm-build-guest`) as fallback.

## GPU Features

Two levels of GPU acceleration exist, wired as cargo features:

- `scroll-zkvm-integration/cuda` (→ `scroll-zkvm-prover/cuda` → `openvm-sdk/cuda`): STARK proving on GPU.
- `scroll-zkvm-integration/halo2-gpu` (→ `openvm-sdk/halo2-gpu` → `openvm-static-verifier/halo2-gpu` → `snark-verifier-sdk/cuda`): additionally runs the **halo2 (SNARK) aggregation prover on GPU** via `halo2-axiom-gpu`. This needs far more VRAM than STARK proving — `test-e2e-bundle` peaks at ~23.5 GiB, so it only fits on 24 GB-class cards (e.g. RTX 3090/4090).

The Makefile auto-enables `halo2-gpu` when `GPU=1` and the GPU has ≥ 22 GiB VRAM. Override with `HALO2_GPU=1` / `HALO2_GPU=0`:

```bash
GPU=1 make test-e2e-bundle        # 24 GB card: STARK + SNARK both on GPU
GPU=1 HALO2_GPU=0 make test-e2e-bundle  # STARK on GPU, SNARK on CPU
```

### VRAM budgeting with `halo2-gpu` (24 GB cards)

Measured on RTX 4090 during `test-e2e-bundle`:

- The halo2 SNARK prover (k=23 static-verifier circuit) needs **~15 GB of physically free VRAM** at `create_proof` time (SRS upload, pk/advice polynomials, MSM buckets, NTT). These allocations are not chunkable; only the final quotient step chunks itself by `cudaMemGetInfo` free bytes.
- openvm's VPMM memory pool (`openvm-cuda-common`) **never returns physical pages to the OS** — once the pool grows, `cudaMemGetInfo` free bytes stay low for the rest of the process. What matters is *live* GPU allocations at SNARK start.
- If free bytes ≈ 0, the quotient chunking computes `batch_size = 0`, which surfaces as `cudaErrorInvalidConfiguration` (`quotient.cu`) or a SIGFPE (division by zero in MSM `win_num_`) — not a clean OOM.

To keep the live GPU set small before the SNARK phase:

- The aggregation VK is a **release asset** (`releases/dev/{chunk,batch,bundle}/agg_vk.bin`, written by build-guest). `Prover::load_agg_vk()` reads it; `enable_deferral`, `compute_deferral_data`, and the integration `get_agg_vk()` all use it instead of building the child's GPU aggregation prover (~5.7 GB per circuit) just to obtain the VK.
- Integration `get_vk()` uses `PROGRAM_COMMITMENTS` (from `openVmVk.json`) instead of `Prover::get_app_vk()`, which also builds the GPU prover as a side effect.
- The bundle tester calls `chunk_prover.reset()` / `batch_prover.reset()` after `enable_deferral` to drop child SDKs before SNARK.

Do **not** reintroduce `sdk.prover()` / `sdk.agg_vk()` calls in read-only (verification/config) paths — each one silently uploads GiB-scale proving keys that stay live for the process lifetime.

### Dependency note: `halo2-lib` retag

`halo2-axiom-gpu` (pulled in by `snark-verifier-sdk/cuda`) must pin `openvm-cuda-common` to the **same stark-backend source** as the rest of the graph, or resolution fails with a `links = "cuda-common"` conflict. axiom-crypto **retagged `halo2-lib` v0.5.4** (commit `6522c1c5` → `a69fdee7`) to fix exactly this (`halo2-axiom-gpu` tag `v1.0.0-rc.2` → `v1.0.0`); the code diff is semantically nil. `Cargo.lock` is pinned to the new commit — if a stale lock ever resolves `halo2-axiom-gpu` to `v1.0.0-rc.2`, run `cargo update -p halo2-base` (scoped, safe) to re-resolve the moved tag.

## Build & Test Commands

```bash
# Force rebuild all guest assets (required after OpenVM upgrade).
# Default RECOMPUTE_MODE=auto falls back to local generation if the download fails.
# Use RECOMPUTE_MODE=yes to skip the download and force local generation.
OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 cargo run --release -p scroll-zkvm-build-guest -- --mode force

# Run end-to-end tests (ALWAYS use make, never raw cargo test)
GPU=1 make test-e2e-bundle
GPU=1 make test-e2e-batch
GPU=1 make test-single-chunk
GPU=1 make test-multi-chunk
```

**⚠️ CRITICAL: Always use `make` for integration tests.**
The Makefile sets `RUST_MIN_STACK=16777216` (16 MB) and `CARGO_CONFIG_FLAG`. Running `cargo test` directly skips both, which causes:
- Stack overflow during prover initialization (default Rust stack is only ~2 MB)
- Missing CUDA features if `GPU=1` is set but `--features scroll-zkvm-integration/cuda` is not passed

**⚠️ CRITICAL: Use `--release` for any test that exercises halo2 verifier generation.**
The `test_verifier` test in `scroll-zkvm-build-guest` builds the full bundle SDK and runs
`generate_halo2_verifier_solidity()`. In debug mode this is orders of magnitude slower and
can waste hours of CPU time. Always run it as:
```bash
cargo test --release -p scroll-zkvm-build-guest test_verifier
```

## Deferral Model (OpenVM v2+)

OpenVM v2 replaces the traditional root-verifier recursion with a **deferred compute model**:

- **Chunk** (leaf circuit, 42 AIRs): no deferral
- **Batch** (aggregation, 44 AIRs): defers child STARK verification to the root
- **Bundle** (aggregation, 44 AIRs): defers child STARK verification to the root

The extra 2 AIRs in batch/bundle come from the deferral extension.

### Deferral circuit must use the parent VM's memory layout

The `MultiDeferralCircuitProver` (verify-stark deferral circuit) is constructed from the **child's aggregation VK**, but its `memory_dimensions` and `num_user_pvs` must come from the **parent's VM config** (the batch or bundle circuit that calls `verify_stark`). Using the child's config causes the deferral circuit to write public values to the wrong location in the parent VM, leading to `Proof verification failed for commit ...` inside the batch/bundle guest.

### Key configuration that must match between prover and verifier

| Parameter | Prover (`crates/prover/src/prover/mod.rs`) | Verifier (`crates/build-guest/src/main.rs`) |
|-----------|---------------------------------------------|---------------------------------------------|
| `AggregationTreeConfig` | `num_children_internal: 3, num_children_leaf: 4` | Same |
| `MultiDeferralCircuitProver` | Built from child SDK in `enable_deferral()` | Built from batch SDK in `generate_evm_verifier()` |
| `agg_params` | `leaf_params + internal_params` (100-bit security) | Same |

If any of these mismatch, the EVM verifier will reject proofs with `ProofVerificationFailed()`.

## Important File Paths

| File / Dir | Purpose |
|------------|---------|
| `releases/dev/{chunk,batch,bundle}/app.vmexe` | Guest executables |
| `releases/dev/{chunk,batch,bundle}/agg_vk.bin` | Serialized aggregation VK (read by `Prover::load_agg_vk`) |
| `releases/dev/verifier/openVmVk.json` | Program commitments loaded by integration tests |
| `releases/dev/verifier/verifier.bin` | EVM verifier bytecode |
| `crates/circuits/*-circuit/openvm.toml` | Guest VM configs (FRI params, PoW bits) |
| `crates/circuits/*-circuit/commitments.rs` | Hardcoded commitment arrays |
| `~/.openvm/params/kzg_bn254_24.srs` | Halo2 KZG SRS (2 GB) |
| `~/.openvm/agg_stark.{pk,vk}` | Cached aggregation proving/verifying keys |
| `.output/` | Integration test outputs (proofs, intermediate files) |

## Guest Config Notes

- `chunk-circuit`: requires `system.config.continuation_enabled = true`
- `batch-circuit` / `bundle-circuit`: aggregation FRI params are supplied in code via `AggregationConfig { params: default_agg_params() }`; the checked-in `openvm.toml` files do not contain `leaf_fri_params`
- FRI params format in OpenVM v2: `commit_proof_of_work_bits` + `query_proof_of_work_bits`
