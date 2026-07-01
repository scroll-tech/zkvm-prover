# AGENTS.md — scroll-zkvm-prover

Critical context for AI agents working on this repo. Read this before making changes, especially around OpenVM upgrades or guest builds.

## Project Structure

- **Guest circuits**: `crates/circuits/{chunk,batch,bundle}-circuit/` — RISC-V ELFs compiled to `.vmexe`
- **Build tool**: `crates/build-guest/` — generates guest assets, commitments, verifier contract
- **Host prover**: `crates/prover/` — loads guest executables and runs STARK/SNARK proving
- **Integration tests**: `crates/integration/` — end-to-end tests (chunk → batch → bundle)
- **Asset outputs**: `releases/dev/{chunk,batch,bundle,verifier}/`
- **Test outputs**: `.output/` — cached proofs and intermediate artifacts

## Multi-zkVM Backend Layout

OpenVM is the production backend and lives in this main workspace. Additional zkVM
backends are prototyped in **isolated sibling Cargo workspaces**, because each zkVM
pulls an incompatible `revm`/`alloy` dependency graph:

- `sp1/` — SP1 v6.3 backend (chunk→batch→bundle with recursion; see `sp1/AGENTS.md`).
- `zisk/` — ZisK v0.18 backend, chunk tier only for now (see `zisk/AGENTS.md` and
  `docs/zisk-backend-assessment.md`). batch/bundle are stubs pending ZisK recursion.

Shared, backend-agnostic pieces (so adding the Nth backend is mechanical):

- `crates/types/{base,chunk,batch,bundle}` — Scroll business logic. OpenVM-specific
  crypto is behind the `openvm` feature; SP1/ZisK guests build these without it.
- `crates/backend` (`scroll-zkvm-backend`) — a backend-neutral interface: the
  `ZkvmBackend` trait plus neutral `ProofEnum`/`ProgramKey`/`ProofStat` (opaque bytes +
  metadata, no zkVM SDK deps). Each backend implements this host-side contract.

Speed comparisons: `docs/benchmark-sp1-vs-openvm.md`, `docs/benchmark-sp1-vs-zisk.md`.

When editing the shared `crates/types/*`, keep them compiling for all backends: do not
add an unconditional OpenVM dependency; gate it behind the `openvm` feature.

## OpenVM Version Sensitivity

This project uses **OpenVM** as its ZKVM. Guest executables (`.vmexe`) and host code **must be built from the exact same OpenVM version**. Even a minor version bump can change:

- The guest/host data layout (hint streams, public inputs)
- The `root_verifier.asm` format
- The Halo2 SRS degree requirement (e.g. `k=23` → `k=24`)
- The EVM verifier contract ABI
- Field algebra APIs (`from_canonical_u32` → `from_int`)
- ECC constructor signatures (some became `unsafe`)

### After ANY OpenVM version upgrade, you MUST:

1. **Update the hardcoded version string** in `crates/build-guest/src/verifier.rs`:
   ```rust
   let openvm_version = "v1.6"; // MUST match Cargo.toml git rev
   ```

2. **Force-rebuild ALL guest assets** (auto mode skips existing files):
   ```bash
   cargo run --release -p scroll-zkvm-build-guest -- --mode force
   ```
   This regenerates: `app.elf`, `app.vmexe`, `root_verifier.asm`, commitment `.rs` files, and `openVmVk.json`.

3. **Verify commitments were updated** — check that `*_exe_commit.rs` and `*_vm_commit.rs` files changed, and that `openVmVk.json` timestamps are fresh.

4. **Clear global OpenVM caches** in `~/.openvm/`:
   ```bash
   rm -f ~/.openvm/agg_stark.pk ~/.openvm/agg_stark.vk ~/.openvm/root.asm
   ```
   These are cached proving keys. They are **not** automatically invalidated on version bumps.

5. **Check SRS params** in `~/.openvm/params/`:
   - OpenVM v1.5.0+ requires `kzg_bn254_24.srs` (2 GB)
   - Earlier versions used `kzg_bn254_23.srs` (1 GB)
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
**Cause**: Stale guest assets (`app.vmexe` or `root_verifier.asm`) from a previous OpenVM version.
**Fix**: Follow all 6 steps above.

### `UnexpectedEof` in `CacheHalo2ParamsReader::read_params`
```
UnexpectedEof: failed to fill whole buffer
```
**Cause**: `~/.openvm/params/kzg_bn254_24.srs` is missing, empty, or truncated.
**Fix**: Ensure a valid 2 GB SRS file exists at that exact path.

### Docker build fails with stale CID
The `build-guest.sh` script may fail if a stale `build-guest.cid` file exists. Use local build (`cargo run -p scroll-zkvm-build-guest`) as fallback.

## Build & Test Commands

```bash
# Force rebuild all guest assets (required after OpenVM upgrade)
cargo run --release -p scroll-zkvm-build-guest -- --mode force

# Run end-to-end tests (ALWAYS use make, never raw cargo test)
GPU=1 make test-e2e-bundle
GPU=1 make test-e2e-batch
GPU=1 make test-e2e-chunk
```

**⚠️ CRITICAL: Always use `make` for integration tests.**
The Makefile sets `RUST_MIN_STACK=16777216` (16 MB) and `CARGO_CONFIG_FLAG`. Running `cargo test` directly skips both, which causes:
- Stack overflow during prover initialization (default Rust stack is only ~2 MB)
- Missing CUDA features if `GPU=1` is set but `--features scroll-zkvm-integration/cuda` is not passed

## Important File Paths

| File / Dir | Purpose |
|------------|---------|
| `releases/dev/{chunk,batch,bundle}/app.vmexe` | Guest executables |
| `releases/dev/verifier/openVmVk.json` | Program commitments loaded by integration tests |
| `crates/circuits/*-circuit/openvm.toml` | Guest VM configs (FRI params, PoW bits) |
| `crates/circuits/*-circuit/commitments.rs` | Hardcoded commitment arrays |
| `~/.openvm/params/kzg_bn254_24.srs` | Halo2 KZG SRS (2 GB) |
| `~/.openvm/agg_stark.{pk,vk}` | Cached aggregation proving/verifying keys |
| `.output/` | Integration test outputs (proofs, intermediate files) |

## Guest Config Notes

- `chunk-circuit`: requires `system.config.continuation_enabled = true`
- `batch-circuit` / `bundle-circuit`: include `leaf_fri_params` with `num_queries = 193`, `commit_proof_of_work_bits = 20`
- FRI params format changed in OpenVM 1.6.0: `proof_of_work_bits` → `commit_proof_of_work_bits` + `query_proof_of_work_bits`
