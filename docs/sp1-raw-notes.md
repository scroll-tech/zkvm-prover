# SP1 zkVM (v6.1.0) — Raw Research Notes

Sources: Succinct docs, GitHub releases, `eth-act/ere` compatibility table, SP1 blog posts, community benchmarks.

---

## 1. Architecture

- **ISA**: RISC-V. `eth-act/ere` lists SP1 v6.1.0 as targeting `RV64IMA` (64-bit RISC-V with multiplier and atomics). Guest programs compile to a standard RISC-V ELF using the Succinct toolchain (`cargo prove build` / `SP1RustRv64imaCustomized`).
- **CPU-like zkVM**: every instruction is proven. Programs are written in Rust (std supported) or any LLVM-compiled language.
- **Continuation / large-program support**: SP1 splits execution into **shards** (contiguous batches of cycles). Each shard gets its own STARK proof; shards are then recursively reduced into a single constant-size **compressed** proof. This is automatic for a single ELF.
- **Aggregation / recursion**:
  - Docs: *“SP1 supports proof aggregation and recursion, which allows you to verify an SP1 proof within SP1.”*
  - To verify a proof inside the guest, use `sp1_zkvm::lib::verify::verify_sp1_proof(vkey, public_values_digest)` with the `verify` feature enabled.
  - The input proof must be a **compressed** SP1 proof.
  - The prover streams the proof in automatically; the guest only checks vkey and public-values digest.
  - Docs note aggregation is recommended when memory exceeds ~2 GB or execution is extremely long (>120 B cycles), or when you want to combine proofs from different parties.

## 2. Proof System

- **Core proof**: FRI-based STARK over the BabyBear field, built on **Plonky3** (acknowledged in SP1 README). Uses cross-table lookups / LogUp, blowup factor 2.
- **Proof types** (from Succinct docs):
  - `Core` — list of STARKs, total proof size proportional to execution.
  - `Compressed` — constant-size STARK, usable for recursive verification inside SP1.
  - `Groth16` — ~260-byte SNARK, ~270k gas on EVM. Uses Aztec Ignition ceremony + Succinct entropy contributions (trusted setup).
  - `Plonk` — ~868-byte SNARK, ~300k gas on EVM, no trusted setup, ~1.5 min slower than compressed.
- **STARK → SNARK wrapping**: SP1 uses gnark to wrap the final recursive STARK into a BN254 Groth16 or Plonk proof for EVM verification.
- **EVM verifier contracts**: `succinctlabs/sp1-contracts` provides `ISP1Verifier` and a version-routing `SP1_VERIFIER_GATEWAY`. Deployed on Ethereum mainnet, Base, Arbitrum, Scroll, etc.

## 3. Performance / Cycle Characteristics

- General claims: SP1 is 4–28× faster than other zkVMs on blockchain workloads; SP1 Reth block proofs ~$0.01–0.02/tx; SP1 Turbo GPU cluster can verify an Ethereum mainnet block in ~40 s.
- Concrete benchmark (CFrontier Labs, Taiko block, gas limit ~5.9 M, 488,808,529 cycles):
  - Hardware: AMD Ryzen 9 9950X, 16 cores, 96 GB RAM.
  - Total proving time: ~1.5 h.
  - Shard proving: ~1 h, peak memory 50 GB.
  - Recursive reduction: ~0.5 h.
- SP1 Reth (archived POC) benchmarks (64 vCPU / 512 GB RAM):
  - 10–26 M gas blocks → 240–344 M cycles → 42–64 min end-to-end.
- OP Succinct v4.3.0 recommends CPU nodes with 96 GB RAM.
- Memory guidance: single zkVM process limited to ~2 GB; executions >120 B cycles may need explicit aggregation.

## 4. Precompiles

Precompiles are exposed as `ecall` system calls and implemented as dedicated STARK tables.

From the syscall spec (v6.x-era):

- **Hashes**: `syscall_sha256_extend/compress`, `syscall_keccak_permute`.
- **Signatures / ECC**:
  - secp256k1: add, double, decompress.
  - ed25519: add, decompress.
  - BN254: add, double; also field/Fp/Fp2 ops in later versions; `syscall_uint256_mulmod`, `sys_bigint`.
  - BLS12-381: add, double, decompress; field ops.
- **Proof recursion**: `syscall_verify_sp1_proof`.
- **Other**: `syscall_enter_unconstrained` / `syscall_exit_unconstrained`, hint stream syscalls.

Reported cycle reductions:

- alt_bn128_pair (revm/EVM precompile): 155 M → 6.6 M cycles.
- Groth16 verification inside SP1: ~174 M → 9.4 M cycles.
- BLS12-381 sync-committee verification (512 sigs): 6.7 B → 49 M cycles.

Note: there is no dedicated `bn254_pairing` syscall; pairing is accelerated through the BN254 curve/field precompiles plus the `substrate-bn` patch.

## 5. License / Maturity / Maintenance

- **License**: MIT / Apache-2.0 dual license (open-source constraints, no obfuscation).
- **Status**: Succinct advertises SP1 as production-ready. Audits by Veridise, Cantina, Zellic, KALOS; bug-bounty program; mainnet deployments; >$1B TVL claimed.
- **Maintenance**: very active. Latest release at time of research is v6.2.2 (2026). v6.1.0 was released 2025. MSRV is Rust 1.91.
- **Security note**: a Jan 2025 LambdaClass/3MI disclosure described soundness bugs in SP1 SDK v3.4.0 (proof forgery via unconstrained commit digest and recursion edge case). These were patched and are not present in v6.x, but illustrate the risk of rapid releases.

## 6. Production zkEVM / Rollup Usage

- **OP Succinct** — OP Stack ZK validity / fault proofs. v4.3.0 uses SP1 SDK v6.1.0.
- **RSP (Reth Succinct Processor)** — EVM block execution proofs using Reth + SP1.
- **Taiko** — multi-prover model includes SP1.
- **Polygon** — pessimistic proofs / AggLayer integrations.
- **Celestia / Avail** — Blobstream, Vector light-client bridges.
- **SP1 Helios** — Ethereum ZK light client.
- **Scroll** is mentioned as having collaborated on custom precompiles, but Scroll’s own production zkEVM prover (“Euclid”) uses OpenVM, not SP1.

## 7. Fit for scroll-zkvm-prover

Relevant observations:

- **Multi-tier aggregation**: SP1 natively supports sharding + recursive compression. For an explicit `chunk → batch → bundle` pipeline, each tier would be a separate SP1 ELF; lower-tier proofs are produced as `Compressed` proofs and verified in the next tier via `verify_sp1_proof`. The final bundle ELF is wrapped to Groth16/Plonk by the SDK. This is feasible but not a built-in abstraction.
- **EVM verifier**: mature, deployed, ~270–300k gas.
- **Heavy precompiles**: strong built-in set (keccak, sha256, secp256k1, ed25519, BN254, BLS12-381, bigint). Scroll-specific curves/hashes would likely require custom precompiles; SP1’s open-source table system supports this but is non-trivial.
- **Large witnesses**: stdin is raw bytes; public values are unlimited and hashed into a digest. Guest memory is ~2 GB, so very large witnesses must be Merkleized or streamed.
- **ISA / toolchain mismatch**: SP1 v6.1.0 uses RV64IMA, whereas the current scroll-zkvm-prover uses OpenVM v1.6. Guest code, commitment generation, and host SDK calls would need porting.
- **Version sensitivity**: each SP1 release changes ELF builds / verifying keys; `op-succinct` release notes explicitly warn that upgrades require contract redeployment with new keys. This is similar to OpenVM’s version-sensitivity note in `AGENTS.md`.
