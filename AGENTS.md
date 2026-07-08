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

This project uses **OpenVM v2.0.0-rc.3** as its ZKVM. Guest executables (`.vmexe`) and host code **must be built from the exact same OpenVM version**. Even a minor version bump can change:

- The guest/host data layout (hint streams, public inputs)
- The Halo2 SRS degree requirement
- The EVM verifier contract ABI
- Field algebra APIs
- ECC constructor signatures

### How to update OpenVM dependencies correctly

OpenVM is declared as a **git dependency** (`branch = "develop-v2.0.0-rc.3"`) in `Cargo.toml`, but the exact commit is pinned in `Cargo.lock`. Running a bare `cargo update` will **not** move the git branch forward; instead it will only bump unrelated crates.io packages (e.g. `alloy`, `revm`) which often break compatibility with the `scroll-tech/reth` and `sbv` forks.

**Do NOT run a global `cargo update` unless you are prepared to upgrade the entire `alloy`/`revm`/`reth`/`sbv` dependency chain together.**

To check whether the branch actually has new commits:
```bash
git ls-remote https://github.com/openvm-org/openvm.git develop-v2.0.0-rc.3
```
If the returned SHA differs from the one recorded in `Cargo.lock`, update only the OpenVM packages:
```bash
cargo update -p openvm
```
Then rebuild guests and run tests as described below.

### After ANY OpenVM version upgrade, you MUST:

1. **Update the hardcoded version string** in `crates/build-guest/src/verifier.rs`:
   ```rust
   let openvm_version = "v2.0.0-rc.3"; // MUST match openvm-solidity-sdk tag
   ```

2. **Force-rebuild ALL guest assets** (auto mode skips existing files):
   ```bash
   OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 RECOMPUTE_MODE=yes cargo run --release -p scroll-zkvm-build-guest -- --mode force
   ```
   This regenerates: `app.elf`, `app.vmexe`, commitment `.rs` files, `openVmVk.json`,
   and the EVM verifier (`verifier.sol` + `verifier.bin`).

   > `RECOMPUTE_MODE=yes` is **required** to regenerate the EVM verifier bytecode.
   > Without it the build only downloads the Solidity source, producing an empty
   > bytecode file that will cause `verify_evm_proof` to fail.

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
   - OpenVM v2.0.0-rc.3 requires `kzg_bn254_24.srs` (2 GB)
   - If the file is empty/corrupted, replace it (check for `.1` or `.part` suffixes from interrupted downloads)

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
- The verifier was built **without** `RECOMPUTE_MODE=yes` (uses `Sdk::riscv32()` default)
- The verifier was built **without** the deferral prover, but the proof uses deferral (batch/bundle)
- The verifier's `AggregationTreeConfig` does not match the prover's (`num_children_internal/leaf`)

**Fix**: Regenerate with:
```bash
OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 RECOMPUTE_MODE=yes cargo run --release -p scroll-zkvm-build-guest -- --mode force
```

### `cargo update` breaks compilation with alloy/revm type mismatches
**Symptoms**: Errors like `missing verify_and_compute_signer_unchecked in implementation` (alloy) or `mismatched types` between `revm_primitives::hardfork::SpecId` and `SpecId` (revm).
**Cause**: A global `cargo update` bumps `alloy` to 1.8.x and `revm` to 30.2.0, but the `scroll-tech/reth` and `sbv` forks were built against older versions. The `[patch.crates-io]` table pins `revm` to `scroll-v91` (30.1.1), which no longer satisfies the newer `alloy-evm` requirements, leading to duplicate registry versions of `revm-handler` / `revm-primitives` in the dependency graph.
**Fix**: Restore the original `Cargo.lock` (`git checkout HEAD -- Cargo.lock`) and update only what you actually need (e.g. `cargo update -p openvm`).

### Docker build fails with stale CID
The `build-guest.sh` script may fail if a stale `build-guest.cid` file exists. Use local build (`cargo run -p scroll-zkvm-build-guest`) as fallback.

## Build & Test Commands

```bash
# Force rebuild all guest assets (required after OpenVM upgrade)
OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 RECOMPUTE_MODE=yes cargo run --release -p scroll-zkvm-build-guest -- --mode force

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
