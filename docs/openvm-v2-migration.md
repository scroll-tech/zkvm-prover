# OpenVM v2 Migration Guide

> Document ID: `docs/openvm-v2-migration.md`  
> Scope: scroll-zkvm-prover migration from OpenVM v1.x to v2.0.0-beta.2  
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

1. Read the child SDK's `internal_recursive_prover` to get VK + PCS data.
2. Construct a `DeferredVerifyProver` → `VerifyCircuitProver` → `DeferralProver`.
3. Call `deferral_prover.make_extension(...)` to get `DeferralExtension`.
4. Write `[app_vm_config.deferral]` into the release `openvm.toml`.
5. Build the SDK with `.deferral_prover(deferral_prover)`.

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

- Extracts child's `agg_prover().internal_recursive_prover.get_vk()` and `get_self_vk_pcs_data()`.
- Creates `VerifyProver::new::<DeferralEngine>(...)`.
- Wraps it in `VerifyCircuitProver` and then `DeferralProver`.
- Sets `app_config.app_vm_config.deferral = Some(deferral_ext)`.
- Pre-builds the SDK with `Sdk::builder().deferral_prover(deferral_prover).build()`.

`gen_proof_stark` and `gen_proof_snark` now accept `def_inputs: &[DeferralInput]` and forward them to `sdk.prove(...)` / `sdk.prove_evm(...)`.

### 3.3 `crates/integration/src/lib.rs`

Added helper functions:

- `compute_deferral_data(child_prover, proofs)`: decodes `StarkProof` → `VmStarkProof`, builds `VmStarkVerifyingKey`, computes `RawDeferralResult`s, and produces `input_commits`, `DeferralInput`s, and `DeferralState`s.
- `prove_verify_with_deferral`: passes deferral data to `prover.prove_task_with_deferral()`.
- `TaskProver::prove_task_with_deferral`: extension trait method that sets `stdin.deferrals = def_states` before proving.

### 3.4 `crates/build-guest/src/main.rs`

- Projects are now built sequentially, preserving `prev_sdk`.
- For `batch`/`bundle`, `make_deferral_prover(prev_sdk, &agg_params)` constructs the deferral prover.
- `Sdk::builder().app_config(app_config).agg_params(agg_params).deferral_prover(...).build()` replaces the old `Sdk::riscv32(...)` path.
- The modified `app_config` (with `deferral` section) is serialized back to `releases/dev/{project}/openvm.toml`.

---

## 4. Dependency Additions

New workspace dependencies:

```toml
openvm-deferral-circuit = { git = "...", branch = "develop-v2.1.0-rvr" }
openvm-deferral-guest   = { git = "...", branch = "develop-v2.1.0-rvr" }
openvm-verify-stark-circuit = { git = "...", branch = "develop-v2.1.0-rvr" }
openvm-verify-stark-host    = { git = "...", branch = "develop-v2.1.0-rvr" }
openvm-verify-stark-guest   = { git = "...", branch = "develop-v2.1.0-rvr" }
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

If the SDK is built without `.deferral_prover(...)` **or** without `app_vm_config.deferral = Some(...)`, the transpiler will not include `DeferralTranspilerExtension`. Guest code containing `deferred_compute` instructions will then fail at runtime with an illegal instruction error.

**Symptom**: `UnknownInstruction` or similar during `sdk.execute()`.

### 5.3 `DeferralProver` is not `Clone`

`DeferralProver` does not implement `Clone`. In the prover we worked around this by pre-building the SDK inside `enable_deferral()` and storing the resulting `Sdk` directly, rather than keeping the prover around for lazy initialization.

### 5.4 Child VK availability

`enable_deferral` requires the **child prover's aggregation proving key** to already be loaded. For integration tests this means:

1. Build/load the chunk prover first.
2. Call `batch_prover.enable_deferral(&chunk_prover)`.
3. Only then prove batches.

### 5.5 SRS params

OpenVM v2.0.0-beta.2 requires `kzg_bn254_24.srs` (~2 GB). The Makefile auto-downloads it if missing:

```makefile
SRS_PARAMS_DIR := $(HOME)/.openvm/params
SRS_PARAMS_URL := https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/params
```

### 5.6 EVM verifier recompute

OpenVM v2's Solidity verifier is not yet published to the download endpoint used by `verifier::download_evm_verifier()`. During guest builds you must set:

```bash
RECOMPUTE_MODE=yes cargo run --release -p scroll-zkvm-build-guest
```

This triggers `sdk.generate_halo2_verifier_solidity()` instead of downloading a stale contract.

### 5.7 `openvm.toml` must contain deferral config

`SdkVmConfig::from_toml` will deserialize `deferral = None` if the TOML lacks `[app_vm_config.deferral]`. After a guest build, verify that the generated `releases/dev/{batch,bundle}/openvm.toml` contains:

```toml
[app_vm_config.deferral]
def_circuit_commits = [ [...], [...] ]
```

---

## 6. Testing Checklist

After any OpenVM version bump or guest rebuild:

1. `rm -rf ~/.openvm/agg_stark.pk ~/.openvm/agg_stark.vk ~/.openvm/root.asm`
2. `rm -rf .output/bundle-tests-*/`
3. `RECOMPUTE_MODE=yes make build-guest-local`
4. `GPU=1 make test-e2e-bundle`

If tests fail with `NativeHintSliceSubEx` or `UnexpectedEof`, the root cause is almost always stale guest assets or missing SRS.

---

## 7. References

- OpenVM deferral design (from `openvm-sdk` tests): `crates/sdk/src/tests.rs`
- `openvm-deferral-circuit` extension: `extensions/deferral/circuit/src/extension/mod.rs`
- `openvm-verify-stark-circuit` prover: `guest-libs/verify-stark/circuit/src/prover/mod.rs`
- Original AGENTS.md in repo root for additional OpenVM version sensitivity notes.
