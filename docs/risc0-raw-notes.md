# RISC Zero zkVM (v3.0.5) — Raw Research Notes

Sources: RISC Zero docs (dev.risczero.com), GitHub `risc0/risc0` releases, GitHub `risc0/risc0-ethereum`, `eth-act/ere` README/releases, independent benchmarks, public reporting.
Date: 2026-06-21
Version analyzed: **v3.0.5** (pinned by `eth-act/ere` v0.8.0+, released 2025-02-03, backport fixes in #3694)

---

## 1. Architecture

### ISA
- RISC-V **rv32im** (32-bit, integer + multiply/divide, no floating point).
- Guest compiled to standard RISC-V ELF binary; image ID = Merkle root of initial memory image.
- No native floating point; FP ops emulated in software (~60–140 cycles per basic op).
- All execution is single-threaded; `async`/locks/atomics in guest are useless or harmful.

### Memory model
- ~4 GB addressable memory.
- User memory region: `0x00010000`–`0xBFFFFFFF` (~3 GB) for code, heap, stack.
- Memory split into 1 kB pages.
- Page-in / page-out cost: **1094–5130 cycles** (~1130 average) per page.
- Programs that touch many pages pay heavy paging overhead.

### Continuation / segmentation
- **Continuations** split execution into *segments* so very long executions don't blow up memory.
- Pre-continuations limit was ~16 M cycles; with continuations ~10 B cycles quoted in older docs.
- Each segment is proven independently → *SegmentReceipt*.
- Segments are recursively lifted/joined into a single *SuccinctReceipt*.
- Practical: RISC Zero reports ~1 million RISC-V cycles/second throughput on Bonsai (Q1 2026).

### Recursion / aggregation
- Three circuits:
  1. **RISC-V Circuit** — STARK proving RISC-V execution.
  2. **Recursion Circuit** — separate STARK optimized for cryptographic ops, verifies STARK proofs.
  3. **STARK-to-SNARK Circuit** — R1CS circuit verifying Recursion Circuit outputs.
- Recursion programs: `lift`, `join`, `resolve`, `identity_p254`.
- `lift`: convert SegmentReceipt → SuccinctReceipt.
- `join`: pair-wise merge SuccinctReceipts (binary tree) → one SuccinctReceipt.
- `resolve`: remove an assumption from a conditional receipt (proof composition).
- `identity_p254`: prepare for Groth16 with Poseidon254 hashing.
- **Proof composition**: guest can call `env::verify(receipt, image_id)` to add an *assumption* to the current receipt; assumptions are resolved automatically when producing `SuccinctReceipt` or `Groth16Receipt`.
- This provides **arbitrary aggregation/composition**, but it is a single-level assumption tree resolved by the same recursion tree, not an explicit "multi-tier" chunk→batch→bundle architecture out of the box.

---

## 2. Proof System

### Base proof
- **STARK** over the **Goldilocks/BabyBear** small field (transparent, no trusted setup).
- Uses AIR arithmetization, DEEP-ALI + batched FRI.
- Conjectured 98 bits of security with default params; perfect zero-knowledge.

### SNARK wrapper
- Final receipt compressed to a **Groth16** SNARK (`Groth16Receipt`) over BN254.
- Proof size: ~256 bytes.
- On-chain verifier: `RiscZeroGroth16Verifier` in `risc0/risc0-ethereum`.
- Gas cost: ~200,000–300,000 gas per verification call (depends on public inputs; ~181k pairing base + MSM + scaffolding).
- Groth16 requires a **trusted setup ceremony**; RISC Zero ran one in 2024.

### Receipt kinds
- `CompositeReceipt` — collection of per-segment STARK receipts.
- `SuccinctReceipt` — constant-size STARK after lift/join.
- `Groth16Receipt` — on-chain verifiable SNARK.

### Bonsai / Boundless
- **Bonsai**: hosted SaaS prover (RISC Zero operated). Paid model; ~1M cycles/sec quoted.
- **Boundless**: decentralized proof marketplace incubated by RISC Zero, mainnet September 2025. RISC Zero terminated hosted Bonsai service December 2025, routing all proving through Boundless network.
- Boundless uses "Proof of Verifiable Work" (PoVW) incentives for GPU provers.

---

## 3. Performance / Cycle Counts

### Rule of thumb
- Most RV32IM integer ops: **1 cycle**.
- Bitwise ops / shifts right / div/rem: **2 cycles**.
- Memory load/store: **1 cycle** if page already paged-in, else ~1130 cycles page-in.
- Page-out (dirty page at segment end): ~1130 cycles.
- Floating point: 60–140 cycles per basic op.

### Precompile speeds
| Operation | Approx. cycles |
|-----------|---------------|
| SHA-256 per 64-byte block | ~68 (vs ~2000 pure Rust) |
| Keccak-256 | optimized, no published exact block count |
| 256-bit modular multiply | ~10 |
| secp256k1 point mul | ~80,000 (vs ~800,000 pure) |
| ECDSA verify (secp256k1) | ~160,000 (vs ~1.6M pure) |

### Large-program characteristics
- Proving time scales with total cycles.
- 10–50 M cycle programs on Bonsai: 30 sec to several minutes (Q1 2026).
- Ethereum block proving (R0VM 2.0, April 2025) reportedly down to **44 seconds** from 35 minutes; user memory expanded to 3 GB.
- Memory pressure and paging can dominate cost; programs with >few GB working set need continuations.
- Independent thesis benchmarks (Charles University, 2025): RISC Zero produces **smaller proofs and faster verification** than SP1, but SP1 is generally **faster at proof generation and uses fewer cycles**.

---

## 4. Precompiles / Accelerators

### Native / built-in
- SHA-256
- Keccak-256
- 256-bit modular multiplication (`bigint`)
- RSA modular exponentiation

### Elliptic curves (patched crates)
- secp256k1 (`k256` crate patch)
- secp256r1 / NIST P-256 (`p256`)
- ed25519 (`curve25519-dalek`)
- **BN254** (`substrate-bn` patch)
- **BLS12-381** (`bls12_381` / `blst` patch)

### Pairing support
- BN254 and BLS12-381 precompiles are supported via patched crates.
- R0VM 2.0 (April 2025) specifically added BN254 and BLS12-381 precompiles as key additions.
- Pairing operations are still relatively expensive compared to hashing, but orders of magnitude cheaper than pure RISC-V emulation.

### Application-defined precompiles (zkVM 1.2+)
- Precompiles can be shipped with the application rather than built into the zkVM, avoiding verifier-contract upgrades.
- Based on Zirgen `bigint` architecture + Fiat-Shamir randomness.

---

## 5. License / Maturity / Maintenance

### License
- RISC Zero zkVM: **Apache-2.0** (GitHub README).
- `risc0-ethereum` verifier contracts: Apache-2.0.
- Eth-act/ere: dual MIT / Apache-2.0.

### Maturity
- RISC Zero founded 2021; first RISC-V zkVM shipped 2022.
- Raised $2M pre-seed, $12M seed (Bain Capital Crypto), $40M Series A.
- v3.0.5 is a stable release branch (backport fixes from #3694); newer v5.x in development.
- Active development: frequent releases, formal verification efforts (`risc0-lean4` model), GPU prover, Bonsai/Boundless infrastructure.
- ERE (eth-act/ere) is younger (~1 year, 84 stars, 32 open issues) but actively maintained and updated RISC Zero to v3.0.5 in v0.8.0.

### Maintenance status
- RISC Zero: **mature, well-funded, active**.
- Boundless mainnet live since Sep 2025; RISC Zero shut down hosted Bonsai Dec 2025, relying on decentralized network.

---

## 6. Known Production / zkEVM / Rollup Usage

### RISC Zero in rollups
- Positioned as a **proving backend** for "zkVM rollups" — developers write state-transition logic in Rust, run in zkVM, submit receipt to Ethereum.
- Distinct from purpose-built zkEVMs (Scroll, zkSync Era, Polygon zkEVM, Linea) that prove EVM opcodes directly.
- A RISC Zero rollup proves RISC-V execution of a Rust EVM interpreter, adding one abstraction layer.

### Concrete projects
- **Citrea** (Chainway / sov-rollup ecosystem) — uses RISC Zero Bonsai/Boundless adapter for Bitcoin/ZK rollup proofs (tracking issue visible in eth-act/ere search results).
- **Zeth** — RISC Zero's own Ethereum block prover; integrated with L2s.
- **Steel** — library for proving Ethereum contract state/history inside RISC Zero.
- **Kailua** — fast-finality rollup extension using RISC Zero.
- No evidence that Scroll, zkSync, Polygon, Linea, or StarkNet use RISC Zero for their primary zkEVM circuits.

### ERE context
- ERE includes RISC Zero as one of five backends (Airbender, OpenVM, RISC Zero, SP1, ZisK).
- ERE's RISC Zero support: `ere-compiler-risc0`, `ere-prover-risc0`, `ere-platform-risc0`, `ere-verifier-risc0`.
- ERE abstracts compile/execute/prove/verify but **does not abstract SNARK generation or EVM verifier contracts**.
- ERE public-value handling: RISC Zero = unlimited, hashed internally.
- ERE prepends u32 LE length prefix to stdin for RISC Zero because `risc0_zkvm::guest::env::read` needs a length.

---

## 7. Scroll-zkvm-prover Relevance Details

### Multi-tier aggregation
- RISC Zero supports arbitrary receipt aggregation via `join` and proof composition via `resolve`.
- However, the canonical architecture is: many segment receipts → one SuccinctReceipt → one Groth16Receipt.
- A custom **chunk→batch→bundle** hierarchy can be built using proof composition (batch guest verifies chunk receipts; bundle guest verifies batch receipts), but:
  - Each composition layer adds assumptions that must be resolved in the final recursion tree.
  - The final Groth16 wrapper is one proof per "bundle"; intermediate receipts are STARKs.
  - Unlike OpenVM, RISC Zero does not ship a purpose-built "root verifier assembly" or Halo2 KZG SNARK pipeline out of the box; it uses Groth16 over BN254.

### EVM verifier contract
- **Available and mature**: `RiscZeroGroth16Verifier` + `IRiscZeroVerifier` interface.
- Router/emergency-stop infrastructure for upgrades.
- Gas ~200k–300k per call.
- Verifier selector in seal routes to correct implementation.

### Heavy precompile usage
- Strong precompile set: SHA-256, Keccak, BN254, BLS12-381, secp256k1, RSA, 256-bit modular mul.
- Scroll-zkvm-prover likely relies on keccak, BN254, and possibly BLS12-381; RISC Zero covers these.
- Custom EVM-specific precompiles (e.g., EIP-196/197 point ops) are available via BN254 patch.

### Large witness inputs
- Host→guest I/O is through stdin (raw bytes) + journal (public outputs).
- RISC Zero public values are unlimited but hashed internally.
- For very large private witnesses, `env::read_slice` / `write_slice` are efficient.
- Large memory footprint programs hit paging costs and continuations complexity.
- No built-in Merkleized witness streaming like some custom zkEVM stacks; applications must implement chunking/Merkle verification themselves.

### Field / curve alignment
- RISC Zero STARK uses Goldilocks/BabyBear field; final SNARK is BN254 Groth16.
- OpenVM/scroll uses Halo2 KZG over BN254 with `kzg_bn254_24.srs`.
- Both ultimately target BN254 EVM verification, but the proof-system internals differ (STARK vs STARK+Plonk/Halo2).

---

## 8. Version-Specific Notes (v3.0.5)

Release: https://github.com/risc0/risc0/releases/tag/v3.0.5
Backported fixes (#3694):
- Avoid unbounded host buffer allocation during execution (#3545).
- Fix operator precedence issue in `check_bigint_addr` (#3564).
- Constrain `Receipt::journal` to be empty when no output expected (#3632).
- Remove asserts / panicking index operations based on seal data (#3637).
- Set `dev_mode` false in `VerifierContext::empty`; inherit dev_mode in CompositeReceipt assumption verification (#3654).
- On `SuccinctReceipt`, check that `control_id` on seal matches metadata (#3687).
- Docs.rs cfg fix (#3604).
- Add note about codec selection for `Receipt` struct.

These are mostly security/hardening fixes; no major API changes versus v3.0.4.

---

## 9. Key Documents / Links

- https://dev.risczero.com/api/recursion
- https://dev.risczero.com/api/zkvm/composition
- https://dev.risczero.com/api/zkvm/optimization
- https://dev.risczero.com/api/zkvm/precompiles
- https://github.com/risc0/risc0-ethereum/tree/main/contracts
- https://github.com/eth-act/ere
- https://github.com/eth-act/ere/releases/tag/v0.8.0 (RISC Zero v3.0.5 bump)
- https://github.com/risc0/risc0/releases/tag/v3.0.5
