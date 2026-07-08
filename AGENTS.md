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

This project uses **OpenVM v2.0.0-beta.2** on the `develop-v2.1.0-rv64` branch as its ZKVM. Guest executables (`.vmexe`) and host code **must be built from the exact same OpenVM version**. Even a minor version bump can change:

- The guest/host data layout (hint streams, public inputs)
- The Halo2 SRS degree requirement
- The EVM verifier contract ABI
- Field algebra APIs
- ECC constructor signatures

### How to update OpenVM dependencies correctly

OpenVM is declared as a **git dependency** (`branch = "develop-v2.1.0-rv64"`) in `Cargo.toml`, but the exact commit is pinned in `Cargo.lock`. Running a bare `cargo update` will **not** move the git branch forward; instead it will only bump unrelated crates.io packages (e.g. `alloy`, `revm`) which often break compatibility with the `scroll-tech/reth` and `sbv` forks.

**Do NOT run a global `cargo update` unless you are prepared to upgrade the entire `alloy`/`revm`/`reth`/`sbv` dependency chain together.**

To check whether the branch actually has new commits:
```bash
git ls-remote https://github.com/openvm-org/openvm.git develop-v2.1.0-rv64
```
If the returned SHA differs from the one recorded in `Cargo.lock`, update only the OpenVM packages:
```bash
cargo update -p openvm
```
Then rebuild guests and run tests as described below.

### After ANY OpenVM version upgrade, you MUST:

1. **Update the hardcoded version string** in `crates/build-guest/src/verifier.rs`:
   ```rust
   let openvm_version = "v2.0"; // MUST match the OPENVM_VERSION constant in the generated verifier.sol
   ```

2. **Force-rebuild ALL guest assets** (auto mode skips existing files):
   ```bash
   RECOMPUTE_MODE=yes cargo run --release -p scroll-zkvm-build-guest -- --mode force
   ```
   This regenerates: `app.elf`, `app.vmexe`, commitment `.rs` files, `openVmVk.json`,
   and the EVM verifier (`verifier.sol` + `verifier.bin`).

   > `RECOMPUTE_MODE=yes` is **required** to regenerate the EVM verifier bytecode.
   > Without it the build only downloads the Solidity source, producing an empty
   > bytecode file that will cause `verify_evm_proof` to fail.
   >
   > The build also **post-processes** the upstream `OpenVmHalo2Verifier.sol` for
   > rv64 public-value limbs and then **recompiles** the post-processed Solidity
   > with `solc` to produce `verifier.bin`. If `solc` is missing or the
   > post-processing cannot be applied, the build will fail instead of producing
   > a broken `verifier.bin`.

3. **Verify commitments were updated** — check that `*_exe_commit.rs` and `*_vm_commit.rs` files changed, and that `openVmVk.json` timestamps are fresh.

4. **Clear global OpenVM caches** in `~/.openvm/`:
   ```bash
   rm -f ~/.openvm/agg_stark.pk ~/.openvm/agg_stark.vk ~/.openvm/root.asm
   ```
   These are cached proving keys. They are **not** automatically invalidated on version bumps.

5. **Check SRS params** in `~/.openvm/params/`:
   - OpenVM v2 requires `kzg_bn254_24.srs` (2 GB)
   - If the file is empty/corrupted, replace it (check for `.1` or `.part` suffixes from interrupted downloads)

6. **Clear test output cache** before re-running integration tests:
   ```bash
   rm -rf .output/bundle-tests-*/
   ```
   Integration tests reuse cached proofs by default. Stale proofs from a previous OpenVM version will cause failures.

### Patches

- **`openvm-sdk` is intentionally NOT patched.** The upstream crate is used directly. rv64-specific handling of the generated EVM verifier is done at application level in `crates/build-guest`.
- **`openvm-static-verifier` IS patched** (`patches/openvm-static-verifier/`). The patch disables forwarding of `snark-verifier-sdk/cuda`, which keeps the final Halo2 SNARK step on CPU while OpenVM STARK proving uses the GPU backend. On the RTX 3090 (24 GB) machines used for development, the upstream GPU Halo2 SNARK prover exhausts GPU memory after OpenVM STARK proving; the first visible symptom is a `cudaErrorInvalidConfiguration` from halo2-gpu's quotient kernel. The split-process `prover-split` binary works around the memory pressure by giving the bundle SNARK step a fresh CUDA context.

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
- The verifier was built **without** `RECOMPUTE_MODE=yes` (uses `Sdk::riscv32()` default)
- The verifier was built **without** the deferral prover, but the proof uses deferral (batch/bundle)
- The verifier's `AggregationTreeConfig` does not match the prover's (`num_children_internal/leaf`)
- `verifier.bin` is stale and was **not** recompiled from the post-processed `verifier.sol`

**Fix**: Regenerate with:
```bash
RECOMPUTE_MODE=yes cargo run --release -p scroll-zkvm-build-guest -- --mode force
```

### `InvalidPublicValuesLength` (Solidity error `0x604a5115`)
**Cause**: `verifier.bin` still expects rv32 public values (32 bytes), but the proof carries rv64 public-value limbs (64 bytes). This happens when the post-processed `verifier.sol` was written but the bytecode in `verifier.bin` was not recompiled from it.

**Fix**: Regenerate as above; the build-guest now recompiles `verifier.sol` with `solc` automatically.

### `cudaErrorInvalidConfiguration` in halo2-gpu quotient kernel
**Cause**: GPU memory exhaustion during the final Halo2 SNARK step. OpenVM STARK proving on the same GPU leaves less than halo2-gpu's hardcoded 256 MiB reserve, so `query_device_free_bytes_for_chunking()` returns `0`. `_halo2_evaluate_h_max_rows` then returns a `batch_size` of `0`, the quotient kernel is launched with `num_blocks=0`, and CUDA reports `cudaErrorInvalidConfiguration` (`cuda/src/quotient.cu:698`). This is a memory-capacity failure, not a kernel code bug; bypassing the reserve only moves the failure to a later SNARK stage (e.g., `InsufficientGpuMemory` in `extended_from_lagrange_vec_device` or `pk.fixed_values_device()`).

**Fix**: The default `test-e2e-bundle` path now spawns a dedicated `prover-split` subprocess for the bundle STARK + SNARK steps. The subprocess gets a fresh CUDA context, so it is no longer limited by the memory left over from chunk/batch STARK proving. Keep the `openvm-static-verifier` patch in place so the SNARK step runs on CPU; this combination has been verified to pass on an RTX 3090 (24 GB). To disable the subprocess and run in-process, set `SCROLL_ZKVM_SPLIT_STARK_SNARK=0`.

### `cargo update` breaks compilation with alloy/revm type mismatches
**Symptoms**: Errors like `missing verify_and_compute_signer_unchecked in implementation` (alloy) or `mismatched types` between `revm_primitives::hardfork::SpecId` and `SpecId` (revm).
**Cause**: A global `cargo update` bumps `alloy` to 1.8.x and `revm` to 30.2.0, but the `scroll-tech/reth` and `sbv` forks were built against older versions. The `[patch.crates-io]` table pins `revm` to `scroll-v91` (30.1.1), which no longer satisfies the newer `alloy-evm` requirements, leading to duplicate registry versions of `revm-handler` / `revm-primitives` in the dependency graph.
**Fix**: Restore the original `Cargo.lock` (`git checkout HEAD -- Cargo.lock`) and update only what you actually need (e.g. `cargo update -p openvm`).

### `cudaErrorInvalidConfiguration` / `InsufficientGpuMemory` persists after tuning
If you are trying to remove the `openvm-static-verifier` patch and run the upstream GPU Halo2 SNARK on a 24 GB GPU, the following parameter changes were investigated and **did not resolve** the memory exhaustion:

| Tuning attempt | Why it was tried | Result |
|----------------|------------------|--------|
| `AggregationTreeConfig {2,2}` | Smaller fan-out should reduce per-aggregation-step memory | Static-verifier circuit size stayed ~26 M advice cells; same `cudaErrorInvalidConfiguration` failure |
| `segmentation_max_memory` capped at 8 GiB / 2 GiB | Smaller RV64 segments should lower peak STARK memory | No meaningful reduction in per-segment trace size; 2 GiB cap changed failure mode to `InsufficientGpuMemory` but still OOMed |
| Lower WHIR security bits on root params (e.g. 80-bit) | Fewer WHIR queries shrink the static-verifier circuit | Rejected — lowers provable security |

**Conclusion:** On the current OpenVM v2 100-bit-security configuration, the bundle SNARK wrapper circuit is ~26 M Halo2 advice cells. Running STARK and SNARK in the same process leaves the GPU with too little memory for the upstream GPU SNARK prover. The repository now implements a split-process path (`prover-split`) that runs the bundle STARK + SNARK in a fresh CUDA context. With the `openvm-static-verifier` patch (CPU SNARK), this passes on an RTX 3090 (24 GB).

Removing the `openvm-static-verifier` patch to re-enable GPU SNARK was also tested in the split-process subprocess. It still fails with `InsufficientGpuMemory { context: "plonk::prover: pk.fixed_values_device() unavailable", free_bytes: 0 }`, which means the upstream GPU Halo2 SNARK prover itself needs more than 24 GB for this circuit even with a clean CUDA context. Therefore the static-verifier patch is still required on 24 GB GPUs; a GPU with significantly more VRAM would be needed to remove it.

### Docker build fails with stale CID
The `build-guest.sh` script may fail if a stale `build-guest.cid` file exists. Use local build (`cargo run -p scroll-zkvm-build-guest`) as fallback.

## Build & Test Commands

```bash
# Force rebuild all guest assets (required after OpenVM upgrade)
RECOMPUTE_MODE=yes cargo run --release -p scroll-zkvm-build-guest -- --mode force

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

### GPU device selection

OpenVM's CUDA backend initializes a process-wide memory manager on the device that is active when it first allocates. Switching CUDA devices inside the same process after STARK objects have been created breaks that global state (allocations/frees start failing with `cudaErrorInvalidValue`).

To run OpenVM on a specific GPU, set the device **before the process starts**:
```bash
CUDA_VISIBLE_DEVICES=1 GPU=1 make test-e2e-bundle
```
Do not attempt to switch devices from within Rust code.

## Deferral Model (OpenVM v2+)

OpenVM v2 replaces the traditional root-verifier recursion with a **deferred compute model**:

- **Chunk** (leaf circuit, 42 AIRs): no deferral
- **Batch** (aggregation, 44 AIRs): defers child STARK verification to the root
- **Bundle** (aggregation, 44 AIRs): defers child STARK verification to the root

The extra 2 AIRs in batch/bundle come from the deferral extension.

### Key configuration that must match between prover and verifier

| Parameter | Prover (`crates/prover/src/prover/mod.rs`) | Verifier (`crates/build-guest/src/main.rs`) |
|-----------|---------------------------------------------|---------------------------------------------|
| `AggregationTreeConfig` | `num_children_internal: 3, num_children_leaf: 4` | Same |
| `DeferralProver` | Built from child SDK in `enable_deferral()` | Built from batch SDK in `generate_evm_verifier()` |
| `agg_params` | `leaf_params + internal_params` (100-bit security) | Same |

If any of these mismatch, the EVM verifier will reject proofs with `ProofVerificationFailed()`.

## Important File Paths

| File / Dir | Purpose |
|------------|---------|
| `releases/dev/{chunk,batch,bundle}/app.vmexe` | Guest executables |
| `releases/dev/verifier/openVmVk.json` | Program commitments loaded by integration tests |
| `releases/dev/verifier/verifier.bin` | EVM verifier bytecode |
| `releases/dev/verifier/halo2_pk.bin` | Serialized Halo2 proving key used by `prover-split` |
| `crates/integration/src/bin/prover-split.rs` | Subprocess binary for bundle STARK + SNARK proving |
| `crates/circuits/*-circuit/openvm.toml` | Guest VM configs (FRI params, PoW bits) |
| `crates/circuits/*-circuit/commitments.rs` | Hardcoded commitment arrays |
| `~/.openvm/params/kzg_bn254_24.srs` | Halo2 KZG SRS (2 GB) |
| `~/.openvm/agg_stark.{pk,vk}` | Cached aggregation proving/verifying keys |
| `.output/` | Integration test outputs (proofs, intermediate files) |

## Guest Config Notes

- `chunk-circuit`: requires `system.config.continuation_enabled = true`
- `batch-circuit` / `bundle-circuit`: include `leaf_fri_params` with `num_queries = 193`, `commit_proof_of_work_bits = 20`
- FRI params format in OpenVM v2: `commit_proof_of_work_bits` + `query_proof_of_work_bits`
