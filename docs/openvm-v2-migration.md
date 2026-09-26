# OpenVM v2 Migration Guide

> Document ID: `docs/openvm-v2-migration.md`  
> Scope: scroll-zkvm-prover migration from OpenVM v1.x to v2.0.0-rc.3  
> Author: Agent  
> Date: 2026-05-22

---

## 1. Background

OpenVM v2 introduces a **deferred compute model** for proof verification inside the guest VM. In v1, aggregation circuits (batch/bundle) verified child STARK proofs by loading a `root_verifier.asm` file and executing it as inline assembly inside the guest. This approach had several limitations:

- The root verifier ASM was large and tightly coupled to the exact OpenVM version.
- Any change in the aggregation circuit params (e.g. FRI params, leaf config) required regenerating the ASM.
- Guest-side verification was opaque and hard to maintain.

In v2, guest-side proof verification is restructured around **deferral**: the guest declares *what* it wants to verify (by emitting a deferral call with an input commitment and expected output), and the host pre-computes the verification trace off-line. The aggregation circuit only needs to check that the deferred outputs match the expected values.

### Why this matters for scroll-zkvm-prover

Our pipeline is `chunk → batch → bundle`:

- **Chunk**: leaf circuit. No proof verification inside the guest.
- **Batch**: aggregation circuit. Verifies chunk proofs.
- **Bundle**: aggregation circuit. Verifies batch proofs.

Only batch and bundle need the deferral machinery.

---

## 2. High-level Design

### 2.1 Guest-side changes

Instead of inline ASM, the guest now calls:

```rust
openvm_verify_stark_guest::verify_stark::<0>(input_commit, &expected);
```

This is a **deferral call** (index `0`). The guest passes:

- `input_commit`: a 32-byte commitment to the child proof + transcript state.
- `expected`: a `ProofOutput` struct containing `app_exe_commit`, `app_vm_commit`, and `user_public_values`.

The guest does **not** execute the STARK verifier directly. It only asserts that the host-provided deferred output matches the expected values.

### 2.2 Host-side changes

The host must do three things:

1. **Pre-compute deferral inputs** (`DeferralInput`) for every child proof.
2. **Build a `DeferralProver`** using the child circuit's aggregation VK, and register it with the SDK builder.
3. **Inject `DeferralExtension`** into the VM config so the transpiler knows how to translate `deferred_compute` instructions.

The host-to-guest data flow looks like this:

```
Child proofs
    │
    ▼
compute_deferral_data()
    │
    ├── input_commits  ──► guest stdin (read by verify_stark)
    ├── def_inputs     ──► sdk.prove(app_exe, stdin, def_inputs)
    └── def_states     ──► stdin.deferrals
```

### 2.3 Build-guest changes

`build-guest` now builds circuits in dependency order:

```
chunk (no deferral)
    │
    ▼
batch  ── uses chunk SDK to build DeferralProver
    │
    ▼
bundle ── uses batch SDK to build DeferralProver
```

For each aggregation circuit:

1. Read the child SDK's `agg_vk()` to get the full aggregation verifying key.
2. Compute the child's internal-recursive cached commit with `commit_child_vk` so it
   matches what the child root proof exposes.
3. Construct a `DeferredVerifyProver` → `VerifyCircuitProver` →
   `MultiDeferralCircuitProver` → `DeferralAggProver`.
4. Call `multi_deferral_circuit_prover.make_config(vec![SupportedDeferral::VerifyStark])`
   to obtain a `DeferralConfig`.
5. Write `[app_vm_config.deferral]` into the release `openvm.toml`.
6. Build the SDK with `.multi_deferral_circuit_prover(...)` (build-guest) or
   `.deferral_agg_prover(...)` (host prover).

This guarantees that:
- The guest `.vmexe` is transpiled with `DeferralTranspilerExtension`.
- The host SDK knows how to generate deferral proofs at aggregation time.

---

## 3. Key Code Changes

### 3.1 `crates/types/circuit/src/lib.rs`

`AggCircuit::verify_proofs` was rewritten:

- **Before**: loaded `root_verifier.asm` and ran it as inline guest assembly.
- **After**: reads `input_commits` from `openvm::io::read()` and calls `verify_stark::<0>(input_commit, &expected)` for each child proof.

### 3.2 `crates/prover/src/prover/mod.rs`

Added `Prover::enable_deferral(child_prover: &Prover)`:

- Extracts child's `agg_vk()`.
- Computes the child's internal-recursive cached commit via `commit_child_vk`.
- Creates `VerifyProver::new::<DeferralEngine>(...)` using the **parent** VM's memory
  dimensions and public-value count.
- Wraps it in `VerifyCircuitProver`, then `MultiDeferralCircuitProver`, then
  `DeferralAggProver`.
- Uses `multi_deferral_circuit_prover.make_config(vec![SupportedDeferral::VerifyStark])`
  to obtain a `DeferralConfig`.
- Sets `app_config.app_vm_config.deferral = Some(deferral_config)`.
- Pre-builds the SDK with `Sdk::builder().deferral_agg_prover(deferral_agg_prover).build()`.

`gen_proof_stark` and `gen_proof_snark` now accept `def_inputs: &[DeferralInput]` and forward them to `sdk.prove(...)` / `sdk.prove_evm(...)`.

### 3.3 `crates/integration/src/lib.rs`

Added helper functions:

- `compute_deferral_data(child_prover, cached_commit, proofs)`: decodes `StarkProof` → `VmStarkProof`, builds `VmStarkVerifyingKey`, computes `RawDeferralResult`s, and produces `input_commits`, `DeferralInput`s, and `DeferralState`s. The `cached_commit` comes from the parent prover's `deferral_circuit_cached_commits(0)`.
- `prove_verify_with_deferral`: passes deferral data to `prover.prove_task_with_deferral()`.
- `TaskProver::prove_task_with_deferral`: extension trait method that sets `stdin.deferrals = def_states` before proving.

### 3.4 `crates/build-guest/src/main.rs`

- Projects are now built sequentially, preserving `prev_sdk`.
- For `batch`/`bundle`, `make_deferral_prover(prev_sdk, &agg_params)` constructs a `MultiDeferralCircuitProver`.
- `Sdk::builder().app_config(app_config).agg_params(agg_params).multi_deferral_circuit_prover(...).build()` replaces the old `Sdk::riscv32(...)` path.
- The modified `app_config` (with `deferral` section) is serialized back to `releases/dev/{project}/openvm.toml`.

---

## 4. Dependency Additions

New workspace dependencies:

```toml
openvm-deferral-circuit = { git = "...", branch = "develop-v2.0.0-rc.3" }
openvm-deferral-guest   = { git = "...", branch = "develop-v2.0.0-rc.3" }
openvm-verify-stark-circuit = { git = "...", branch = "develop-v2.0.0-rc.3" }
openvm-verify-stark-host    = { git = "...", branch = "develop-v2.0.0-rc.3" }
openvm-verify-stark-guest   = { git = "...", branch = "develop-v2.0.0-rc.3" }
openvm-cuda-backend = { git = "...", branch = "develop-v2" }   # for GPU builds
```

Crates that pull these in:

- `scroll-zkvm-prover`
- `scroll-zkvm-integration`
- `scroll-zkvm-build-guest`

---

## 5. Lessons Learned & Pitfalls

### 5.1 `Sdk::riscv32()` vs `Sdk::builder()`

`Sdk::riscv32(app_params, agg_params)` internally creates an `AppConfig::riscv32(app_params)` and ignores any TOML-level extensions (e.g. deferral). If you need a custom VM config (including deferral), **you must use `Sdk::builder().app_config(app_config).build()`**.

### 5.2 Transpiler must know about deferral

If the SDK is built without `.multi_deferral_circuit_prover(...)` **or** without `app_vm_config.deferral = Some(...)`, the transpiler will not include `DeferralTranspilerExtension`. Guest code containing `deferred_compute` instructions will then fail at runtime with an illegal instruction error.

**Symptom**: `UnknownInstruction` or similar during `sdk.execute()`.

### 5.3 `MultiDeferralCircuitProver` is not `Clone`

`MultiDeferralCircuitProver` does not implement `Clone`. In the prover we worked around this by pre-building the SDK inside `enable_deferral()` and storing the resulting `Sdk` directly, rather than keeping the prover around for lazy initialization.

### 5.4 Child VK availability

`enable_deferral` requires the **child prover's aggregation proving key** to already be loaded. For integration tests this means:

1. Build/load the chunk prover first.
2. Call `batch_prover.enable_deferral(&chunk_prover)`.
3. Only then prove batches.

### 5.5 SRS params

OpenVM v2.0.0-rc.3 requires `kzg_bn254_24.srs` (~2 GB). The Makefile auto-downloads it if missing:

```makefile
SRS_PARAMS_DIR := $(HOME)/.openvm/params
SRS_PARAMS_URL := https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/params
```

### 5.6 EVM verifier recompute

`build-guest` uses `RECOMPUTE_MODE` to decide how to obtain the EVM verifier:

- `auto` (default): download the Solidity verifier from `openvm-solidity-sdk`,
  compile it locally with `solc` to produce `verifier.bin`, and fall back to the
  full local OpenVM verifier generation if the download is unavailable.
- `yes`: always generate the verifier locally.
- `no`: only download; fail if the pre-built verifier is unavailable.

```bash
OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 cargo run --release -p scroll-zkvm-build-guest -- --mode force
```

The `auto` mode avoids the long OpenVM verifier-generation step when a published
Solidity verifier is available, while still producing a usable `verifier.bin` by
compiling the downloaded source.

### 5.7 `openvm.toml` must contain deferral config

`SdkVmConfig::from_toml` will deserialize `deferral = None` if the TOML lacks `[app_vm_config.deferral]`. After a guest build, verify that the generated `releases/dev/{batch,bundle}/openvm.toml` contains:

```toml
[[app_vm_config.deferral.circuits]]
def_type = "VerifyStark"
commit = [...]
```

---

## 6. Testing Checklist

After any OpenVM version bump or guest rebuild:

1. `rm -rf ~/.openvm/agg_stark.pk ~/.openvm/agg_stark.vk ~/.openvm/root.asm`
2. `rm -rf .output/bundle-tests-*/`
3. `OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20 cargo run --release -p scroll-zkvm-build-guest -- --mode force`
4. `GPU=1 make test-e2e-bundle`

If tests fail with `NativeHintSliceSubEx` or `UnexpectedEof`, the root cause is almost always stale guest assets or missing SRS.

---

## 7. References

- OpenVM deferral design (from `openvm-sdk` tests): `crates/sdk/src/tests.rs`
- `openvm-deferral-circuit` extension: `extensions/deferral/circuit/src/extension/mod.rs`
- `openvm-verify-stark-circuit` prover: `guest-libs/verify-stark/circuit/src/prover/mod.rs`
- Original AGENTS.md in repo root for additional OpenVM version sensitivity notes.

---

## 8. Update: v2.0.0-rc.7 → v2.0.0

The repo previously tracked the `develop-v2.0.0-rc.3` branch, but `Cargo.lock` had
actually advanced to commit `031c8b1` (= `v2.0.0-rc.7`). The move to the `v2.0.0`
release (commit `15a7ab6`) was therefore an rc.7 → final bump and required **no host
code changes** — `cargo check` across `types*` / `prover` / `verifier` / `integration`
/ `build-guest` passed with zero warnings and zero errors.

What changed:

- `Cargo.toml`: every `openvm-org/openvm.git` entry moved from
  `branch = "develop-v2.0.0-rc.3"` to `tag = "v2.0.0"`; the three
  `openvm-org/stark-backend.git` entries moved from `branch = "develop-v2"` to
  `tag = "v2.0.0"` (this tag MUST match the one openvm's own `Cargo.toml` pins).
- `Cargo.lock`: refreshed with `cargo metadata` only — no package outside the
  openvm/stark git sources changed version or source (alloy/revm/sbv untouched;
  package count 851 → 851).
- `crates/build-guest/src/verifier.rs`: `solidity_sdk_tag` set to `"v2.0"` and
  `verifier_path` set to `"v2.0-deferral"` to match the published
  `openvm-solidity-sdk` release layout.
- SRS: still `kzg_bn254_24.srs` (unchanged from rc.7); no re-download needed.

Still required to complete the upgrade (per the checklist above): force-rebuild all
guest assets with the default `RECOMPUTE_MODE=auto` (or `yes` to skip the download
attempt), clear stale `.output/` caches, and re-run the `make test-e2e-*` suite.


---

## 9. Update: v2.0.0 → develop-v2.1.0 (RV64)

The move to the `develop-v2.1.0` branch (commit `fd569c7`) is a **major migration**:
OpenVM switches the guest ISA from RV32 to RV64. What changed:

- `Cargo.toml`: every `openvm-org/openvm.git` entry moved from `tag = "v2.0.0"` to
  `branch = "develop-v2.1.0"`; the three `openvm-org/stark-backend.git` entries
  stay on `tag = "v2.0.0"` (that is what openvm's own `Cargo.toml` pins on this
  branch). Crate renames: `openvm-rv32im-guest`/`openvm-rv32im-transpiler` →
  `openvm-riscv-guest`/`openvm-riscv-transpiler`.
- Guest toolchain: `OPENVM_RUST_TOOLCHAIN=nightly-2025-11-20` → `openvm-1.94.0`
  (the openvm rust fork with the built-in `riscv64im-unknown-openvm-elf` target).
  `rust-toolchain.toml` host channel → `nightly-2026-01-18` (openvm-sdk `tco`
  feature); the `riscv32im-unknown-none-elf` target entry was dropped.
- `openvm.toml` (all three circuits): `[app_vm_config.rv32i]`/`rv32m` →
  `rv64i`/`rv64m`.
- SDK API: `Sdk::riscv32`/`AppConfig::riscv32` → `riscv64`; `Sdk::execute*` now
  takes a compiled instance (`sdk.compile_metered_cost(exe)?` then
  `sdk.execute_metered_cost(&compiled, inputs)`; same for `compile`/`execute`).
- Hint stream is 8-byte granular: guest `read_witnesses_rkyv_raw` reads a `u64`
  length prefix (`hint_store_u64!`) then uses `hint_buffer_chunked`.
- User public values are u16 cells (2 LE bytes per cell; `NUM_PUBLIC_VALUES` is
  still 32 cells). Affected spots: guest `verify_proof` expected PVs,
  `aggregated_pi_hashes` in batch/bundle circuits, fabricated
  `AggregationInput.public_values` in integration utils, and the EVM branch of
  `types/src/proof.rs::public_values()`.
- Guest cfg gates: `target_os = "zkvm"` → `target_os = "openvm"`.
- `crates/build-guest/src/verifier.rs`: `solidity_sdk_tag = "v2.1"`,
  `verifier_path = "v2.1-deferral"`. `openvm-solidity-sdk` has no `v2.1` tag yet,
  so the download fails and `auto` mode falls back to local verifier generation.
- EVM verifier workaround: the branch's Solidity template still expects 1 byte
  per public value while the SDK packs u16 cells as 2 LE bytes.
  `crates/build-guest/src/main.rs::patch_verifier_for_u16_public_values`
  rewrites the generated wrapper (length check ×2, per-cell byte expansion) and
  clears the precompiled artifact so `verifier.bin` is recompiled from the
  patched source by `solc`.
- SRS: still `kzg_bn254_24.srs` (unchanged).

Verification: `GPU=1 make test-single-chunk`, `test-multi-chunk`,
`test-e2e-batch`, `test-e2e-bundle` all pass (CUDA, RTX 3090).
