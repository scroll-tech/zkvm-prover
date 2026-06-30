# Ere (eth-act/ere) — Raw Research Notes

Source: https://github.com/eth-act/ere  
Branch analyzed: `master`  
Date: 2026-06-21

---

## 1. What is Ere?

- Tagline: "Compile. Execute. Prove. Verify."
- One ergonomic Rust API, multiple zero-knowledge virtual machines.
- Description: "Unified zkVM Interface & Toolkit"
- Goal: Abstract away differences between zkVM backends so the same guest/host code can target multiple zkVMs with a common trait interface.

---

## 2. Supported zkVM Backends

| zkVM      | Version  | ISA       | GPU | Multi GPU | Cluster | Notes |
|-----------|----------|-----------|-----|-----------|---------|-------|
| Airbender | `73d69b5`| RV32IMA   | ✓   | ✓         |         | Matter Labs |
| OpenVM    | `v1.4.3` | RV32IMA   | ✓   |           |         | Uses `cargo-openvm` v1.4.3 |
| RISC Zero | `v3.0.5` | RV32IMA   | ✓   | ✓         |         | Proves with `r0vm` / `r0vm-cuda` |
| SP1       | `v6.1.0` | RV64IMA   | ✓   |           |         | Uses `sp1-sdk` v6.1.0 |
| ZisK      | `v0.18.0`| RV64IMA   | ✓   | ✓         | ✓       | Polygon Hermez |

Files:
- `crates/prover/{airbender,openvm,risc0,sp1,zisk}/`
- `crates/platform/{...}/`
- `crates/compiler/{...}/`
- `crates/verifier/{...}/`
- `crates/catalog/src/zkvm.rs` defines `zkVMKind` enum.

---

## 3. Architecture

Ere is a **trait-based abstraction layer / SDK adapter**, not a common IR or translation layer. It defines generic host-side and guest-side traits, then provides per-zkVM implementations.

### Crate layout

```
ere/
├── crates/
│   ├── compiler/core          # ere-compiler-core: Compiler trait, Elf type
│   ├── compiler/{zkvm}        # ere-compiler-{zkvm}: per-zkVM compilers
│   ├── prover/core            # ere-prover-core: zkVMProver trait, Input, reports
│   ├── prover/{zkvm}          # ere-prover-{zkvm}: per-zkVM provers
│   ├── platform/core          # ere-platform-core: Platform trait (guest)
│   ├── platform/{zkvm}        # ere-platform-{zkvm}: per-zkVM guest APIs
│   ├── verifier/core          # ere-verifier-core: zkVMVerifier trait, PublicValues
│   ├── verifier/{zkvm}        # ere-verifier-{zkvm}: per-zkVM verifiers
│   ├── dockerized             # ere-dockerized: Docker/gRPC wrapper
│   ├── server/{api,cli,client}# gRPC server for dockerized mode
│   ├── catalog                # ere-catalog: zkVMKind, CompilerKind, versions
│   ├── codec                  # ere-codec: Encode/Decode + macros
│   └── util/*                 # build, compile, test, tokio helpers
```

### Core traits

#### `ere_compiler_core::Compiler`
- `crates/compiler/core/src/compiler.rs`
```rust
pub trait Compiler {
    type Error: 'static + Send + Sync + Error;
    fn compile(&self, guest_directory: impl AsRef<Path>, args: &[String]) -> Result<Elf, Self::Error>;
}
```

#### `ere_prover_core::zkVMProver`
- `crates/prover/core/src/prover.rs`
```rust
#[auto_impl(&, Arc, Box)]
pub trait zkVMProver {
    type Verifier: zkVMVerifier;
    type Error: ...;
    fn verifier(&self) -> &Self::Verifier;
    fn execute(&self, input: &Input) -> Result<(PublicValues, ProgramExecutionReport), Self::Error>;
    fn prove(&self, input: &Input) -> Result<(PublicValues, Proof, ProgramProvingReport), Self::Error>;
    fn verify(&self, proof: &Proof) -> Result<PublicValues, Self::Error>;
    fn program_vk(&self) -> &ProgramVk;
    fn name(&self) -> &'static str;
    fn sdk_version(&self) -> &'static str;
}
```

#### `ere_verifier_core::zkVMVerifier`
- `crates/verifier/core/src/verifier.rs`
```rust
#[auto_impl(&, Arc, Box)]
pub trait zkVMVerifier: 'static + Send + Sync + Clone + Copy + Debug {
    type ProgramVk: Encode + Decode;
    type Proof: Encode + Decode;
    type Error;
    fn verify(&self, proof: &Self::Proof) -> Result<PublicValues, Self::Error>;
    fn program_vk(&self) -> &Self::ProgramVk;
    fn name(&self) -> &'static str;
    fn sdk_version(&self) -> &'static str;
}
```

#### `ere_platform_core::Platform`
- `crates/platform/core/src/platform.rs`
- Guest-side trait. Defaults use a `zkvm-standards` C ABI for `read_input`/`write_output`.
- Methods: `read_input`, `write_output`, `print`, `cycle_count`, `cycle_scope_*`.

---

## 4. How It Abstracts Over ZKVMs

- **Common data types**: `Elf`, `Input`, `PublicValues`, `ProgramExecutionReport`, `ProgramProvingReport`, `ProverResource`.
- **Host/guest I/O is raw bytes**: serialization is user-defined; Ere just pipes bytes. For Airbender/RISC0 it prepends a u32 length prefix.
- **Per-zkVM crates** implement the core traits.
- **Dockerized mode**: `ere-dockerized` + `ere-server` provide a gRPC-based wrapper so users don't need local SDKs.
- **Public-value size handling is backend-specific** (see README table).
- **Guest platform trait**: `Platform` + per-zkVM `OpenVMPlatform`, `SP1Platform`, etc.

### Important concrete files
- OpenVM prover: `crates/prover/openvm/src/prover.rs`
- OpenVM verifier: `crates/verifier/openvm/src/verifier.rs`
- OpenVM compiler: `crates/compiler/openvm/src/rust_rv32ima_customized.rs`
- OpenVM platform: `crates/platform/openvm/src/platform.rs` (re-exported)
- SP1 prover: `crates/prover/sp1/src/prover.rs`
- RISC0 prover: `crates/prover/risc0/src/prover.rs`

---

## 5. License, Maturity, Maintenance

- **License**: Dual MIT / Apache-2.0 (workspace `Cargo.toml` and README).
- **Version**: `0.12.2` (workspace).
- **MSRV**: Rust 1.88.
- **Created**: 2025-05-11.
- **Last push**: 2026-06-16 (`chore(master): release 0.12.2`).
- **Stars**: 84; Forks: 25; Open issues: 32.
- **Contributors**: 14 (top: han0110 179, kevaundray 120).
- **Releases**: Automated release-please workflow (0.12.2 latest).
- **Status**: Active development, young (≈1 year old), small but engaged team.

---

## 6. Relevance to scroll-zkvm-prover

### OpenVM version mismatch
- scroll-zkvm-prover uses OpenVM **v1.6** (per `AGENTS.md` and project context).
- Ere supports OpenVM **v1.4.3** only.
- OpenVM versions are highly sensitive; Ere would need an upgrade or a fork.

### Proof kinds / EVM verifier
- Ere's OpenVM `prove()` returns an **aggregated STARK proof** (`VmStarkProof`), not a SNARK/EVM-verifiable proof.
- `OpenVMVerifier` verifies the STARK proof with a bundled `agg_stark.vk`.
- There is **no SNARK/Groth16/Plonk/EVM verifier abstraction** in the core traits.
- scroll-zkvm-prover produces SNARK proofs and a Solidity verifier contract; Ere's abstraction does not currently cover that.

### Aggregation / continuation
- Ere OpenVM prover calls `sdk.prove(app_exe, stdin)` with aggregation keys from `~/.openvm/agg_stark.pk`.
- No explicit SNARK compression step visible.
- No explicit multi-tier aggregation like scroll-zkvm-prover's chunk → batch → bundle.

### Guest program model
- Ere's `Platform` + `Input` model is much simpler than scroll's complex guest circuits.
- Ere is designed for "basic" zkEVM programs; scroll-zkvm-prover has deep OpenVM-specific commitment generation, `root_verifier.asm`, EVM verifier contract, etc.

### Potential uses
- Could serve as an **inspiration or partial dependency** for trait abstractions (`Compiler`, `zkVMProver`, `zkVMVerifier`).
- Could be used for **experimental multi-zkVM benchmarking** of simple programs.
- Not a drop-in replacement for scroll-zkvm-prover's OpenVM-specific pipeline.

---

## 7. Key Observations

- Ere is **not** a common IR; it is an SDK adapter.
- It does **not** hide ISA differences — guests still use per-zkVM platform crates and per-zkVM entrypoints.
- It provides a **uniform host API** for compile/execute/prove/verify.
- It does **not** currently abstract SNARK generation or EVM verification.
- It has **mature Docker/gRPC infrastructure** for users without SDKs installed.
- It is **actively maintained** but targets different (earlier) zkVM versions than scroll-zkvm-prover.
