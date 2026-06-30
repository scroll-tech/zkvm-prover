# RISC Zero zkVM v3.0.5 — Suitability Assessment for scroll-zkvm-prover

**Date:** 2026-06-21  
**Version analyzed:** RISC Zero `v3.0.5` (pinned by `eth-act/ere` v0.8.0+)  
**Current stack:** scroll-zkvm-prover uses OpenVM v1.6, producing Halo2-KZG SNARK proofs with chunk→batch→bundle aggregation and a Solidity verifier contract.  
**Raw notes:** `docs/risc0-raw-notes.md`

---

## Executive Verdict

**Conditionally suitable — not a drop-in replacement, but viable for a deliberate re-architecture.**

RISC Zero has the core building blocks scroll-zkvm-prover needs (RISC-V zkVM, recursion/aggregation, Groth16 EVM verifier, heavy precompiles). However, it is a **different proof-system family** (STARK→Groth16 instead of OpenVM's STARK→Halo2/KZG) and a **different aggregation model** (binary-tree `lift`/`join`/`resolve` vs. OpenVM's `app_exe` + `root_verifier.asm`). A migration would be a substantial rewrite, not a version bump.

---

## 1. RISC Zero Architecture Summary

| Dimension | RISC Zero v3.0.5 |
|-----------|-----------------|
| **ISA** | RISC-V `rv32im` (32-bit integer + mul/div); no FP unit. Guest = standard ELF binary. |
| **Memory** | ~4 GB addressable; 1 kB pages; page-in/out ~1,130 cycles each. |
| **Base proof** | zk-STARK over Goldilocks/BabyBear field (transparent setup). |
| **Recursion** | Dedicated Recursion Circuit (STARK) with `lift`, `join`, `resolve`, `identity_p254` programs. |
| **SNARK wrapper** | Groth16 over BN254 → `Groth16Receipt` (~256 bytes). |
| **EVM verifier** | `RiscZeroGroth16Verifier` in `risc0/risc0-ethereum`; ~200k–300k gas per verify. |
| **Continuation** | Splits execution into segments; supports very long programs (quoted up to billions of cycles). |
| **Composition** | Guest can `env::verify(receipt, image_id)` to add assumptions; resolved automatically in `Succinct`/`Groth16` receipts. |

---

## 2. Fit Against scroll-zkvm-prover Requirements

### 2.1 Multi-tier aggregation: chunk STARKs → batch STARK → bundle SNARK/EVM proof

**Capability:** Yes, in principle.
- RISC Zero can aggregate many leaf receipts via `lift`/`join` into one `SuccinctReceipt`, then compress to `Groth16Receipt`.
- A custom tiered hierarchy can be built using **proof composition**: a "batch" guest verifies N "chunk" receipts, and a "bundle" guest verifies M "batch" receipts. Assumptions are resolved recursively.

**Gaps / friction:**
- OpenVM's pipeline is hard-wired around `app.vmexe`, `root_verifier.asm`, `agg_stark.pk/vk`, and a Halo2 KZG final SNARK. RISC Zero replaces all of these with its own `SegmentReceipt → SuccinctReceipt → Groth16Receipt` pipeline.
- There is no direct equivalent to OpenVM's "root verifier program" that is itself a zkVM circuit. RISC Zero's final wrapper is a fixed Groth16 circuit over BN254, not a programmable root verifier.
- Aggregation proof size and recursion overhead are different; real-world latency/cost for scroll-sized trees would need benchmarking.

**Assessment:** Feasible but requires redesigning the aggregation layer. Not plug-and-play.

### 2.2 EVM verifier contract output

**Capability:** Strong.
- Mature, deployed Solidity verifier contracts (`RiscZeroGroth16Verifier`, `IRiscZeroVerifier`, router + emergency-stop).
- Stable verifier-selector mechanism for upgrades without contract migrations.
- Proof size ~256 bytes; verification gas ~200k–300k.

**Gaps:**
- The contract ABI and public-input encoding differ from scroll's OpenVM/Halo2 verifier.
- Groth16 requires a **trusted setup ceremony** (RISC Zero ran one in 2024). OpenVM/Halo2 also has SRS trust assumptions but uses a different ceremony/file format (`kzg_bn254_24.srs`).

**Assessment:** EVM output is a strength, but the verifier contract and proof format are not compatible with scroll's existing on-chain contracts.

### 2.3 Heavy precompile usage

**Capability:** Strong.
- Built-in: SHA-256 (~68 cycles/block), Keccak-256, 256-bit modular multiplication.
- Patched crates for: secp256k1, secp256r1, ed25519, **BN254**, **BLS12-381**, RSA, KZG (`c-kzg`).
- R0VM 2.0 (April 2025) specifically added BN254/BLS12-381 precompiles as headline features.

**Gaps:**
- Precompiles are accessed via RISC Zero's patched fork crates, not the upstream crates scroll may already use for OpenVM.
- Any OpenVM-native syscalls or custom extension instructions would have to be re-implemented as RISC Zero precompiles or as ordinary RV32IM code.

**Assessment:** Covers the cryptographic primitives a zkEVM needs, but guest code must be ported to RISC Zero's crate patches.

### 2.4 Large witness inputs

**Capability:** Moderate.
- Host→guest I/O is raw bytes via stdin; public outputs go to the journal.
- RISC Zero public values are unlimited (hashed internally), so bundle public inputs are not a hard limit.
- Continuations let programs exceed single-segment memory limits.

**Gaps:**
- Large memory footprints incur **page-in/out overhead** (~1,130 cycles per page, i.e., ~1.35 cycles/byte for sequential access). This can dominate proving cost for memory-heavy witnesses.
- Unlike OpenVM's continuation model, which scroll already tunes (chunk-level continuation), RISC Zero's segment/page model may require different witness-layout optimizations.
- No built-in Merkleized streaming witness protocol; must be implemented in the guest if needed.

**Assessment:** Works, but witness size and memory locality become first-class optimization concerns. Not clearly better than OpenVM for very large witnesses.

---

## 3. Performance & Maturity Considerations

| Factor | RISC Zero | Note |
|--------|-----------|------|
| **Proving speed** | ~1M cycles/sec on Bonsai/Boundless; generally slower than SP1/OpenVM for CPU-bound workloads. | Independent benchmarks show RISC Zero wins on proof size/verification speed, loses on cycle count and proving time. |
| **Proof size** | Excellent — Groth16 receipts ~256 bytes. | Better than OpenVM/Halo2 for on-chain calldata. |
| **Verification cost** | ~200k–300k gas on Ethereum. | Competitive with other zkVM Groth16 wrappers. |
| **Maturity** | High — founded 2021, $54M raised, mainnet verifier, Bonsai/Boundless infrastructure. | More mature than many alternatives. |
| **Formal verification** | Active (`risc0-lean4` model); deterministic verification of RISC-V circuits claimed for R0VM 2.0. | Positive for security posture. |
| **Decentralized proving** | Boundless mainnet (Sep 2025); RISC Zero shut down hosted Bonsai (Dec 2025). | Prover availability now depends on marketplace liquidity. |

---

## 4. Key Blockers

1. **Proof-system mismatch.** scroll-zkvm-prover is built around OpenVM → Halo2/KZG SNARK (`kzg_bn254_24.srs`, `root_verifier.asm`). RISC Zero uses STARK → Groth16. Migration means replacing the entire final SNARK pipeline, verifier contract, and commitment/key artifacts.

2. **Guest-circuit rewrite.** scroll's `chunk-circuit`, `batch-circuit`, `bundle-circuit` crates are OpenVM-specific (guest macros, commitment files, hints, public-value layout). They would need to be rewritten for `risc0_zkvm::guest::env` and RISC Zero's composition model.

3. **Aggregation architecture redesign.** OpenVM's root verifier is itself a programmable zkVM program verified by Halo2. RISC Zero's equivalent is a fixed recursion tree + Groth16 wrapper. The chunk→batch→bundle semantics would have to be re-expressed via `env::verify` assumptions and `join` trees.

4. **Proving latency for large programs.** RISC Zero's proving throughput is lower than SP1/OpenVM in public benchmarks. For scroll's large bundle circuits, wall-clock proving time is a risk that can only be resolved by benchmarking the actual workload.

5. **Memory/paging costs.** Large, randomly-accessed witnesses could be expensive due to RISC Zero's 1 kB page model. Careful guest memory layout would be required.

---

## 5. Key Opportunities

1. **Mature EVM verifier ecosystem.** RISC Zero has a stable, audited, upgradeable Solidity verifier and Foundry tooling. scroll would not have to maintain its own verifier contract generation logic.

2. **Smaller on-chain proofs.** Groth16 receipts (~256 bytes) are smaller than typical Halo2/KZG proofs, reducing L1 calldata cost.

3. **Strong precompile coverage.** SHA-256, Keccak, BN254, BLS12-381, secp256k1, RSA, and 256-bit modular arithmetic are supported, matching zkEVM needs.

4. **Decentralized proving option.** Boundless offers an alternative to self-hosted GPU clusters for proof generation, though it introduces marketplace and latency risks.

5. **ERE compatibility.** `eth-act/ere` already abstracts RISC Zero v3.0.5 alongside OpenVM, SP1, etc. If scroll ever wants a multi-backend abstraction, ERE's trait model is a proven starting point (though ERE itself does not abstract SNARK/EVM output).

---

## 6. Recommendation

**Do not migrate scroll-zkvm-prover to RISC Zero as a short-term or drop-in solution.** The cost of rebuilding the guest circuits, aggregation tree, and verifier contracts is comparable to a full prover rewrite.

**Consider RISC Zero as a medium-term alternative if:**
- The project is willing to maintain two proving backends or eventually retire OpenVM.
- A dedicated benchmarking phase shows acceptable proving latency for chunk/batch/bundle workloads.
- The team is prepared to re-architect aggregation around RISC Zero's `lift`/`join`/`resolve` composition model rather than OpenVM's root-verifier model.
- The benefits of RISC Zero's mature EVM verifier, smaller proofs, and decentralized proving market outweigh the migration engineering cost.

**Next step if pursued:** build a minimal RISC Zero proof-of-concept that proves a single simplified chunk circuit, aggregates a few chunk receipts into a batch, and verifies the resulting Groth16 receipt on a local EVM. This will surface the real cycle counts, memory costs, and latency before committing to a full migration.
