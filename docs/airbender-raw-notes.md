# Airbender zkVM Research Notes (commit 73d69b5)

## 1. What is Airbender?

- ZKsync’s RISC-V zkVM / proving layer. Proves execution of RISC-V bytecode for ZKsync OS and general programs.
- GitHub: `matter-labs/zksync-airbender`
- Commit pinned by `eth-act/ere`: `73d69b5` (ERE lists Airbender version `0.5.2`).
- License: dual Apache-2.0 / MIT.

Sources:
- <https://github.com/matter-labs/zksync-airbender>
- <https://github.com/eth-act/ere> (ERE catalog lists Airbender `0.5.2`, `RV32IMA`)
- Raw README at 73d69b5: <https://raw.githubusercontent.com/matter-labs/zksync-airbender/73d69b5/README.md>

## 2. Architecture / ISA

- ISA: **RISC-V RV32I+M** (32-bit integer + multiply/divide).
- Machine mode only; bare-metal, no OS, no `std`.
- No exception handling under the “trusted code” model: illegal ops / misaligned accesses make constraints unsatisfiable (proof fails).
- Bytecode lives in a ROM region (not generic RAM); no runtime bytecode loading, no loader, `.data` section expected empty.
- Program output convention: write 8 words (32 bytes) to `x10..x17` and halt/loop.
- Max execution length: **≈ 2^30 cycles** at commit `73d69b5`; later `main` docs raise this to ≈ 2^36.
- Execution is split into chunks of **≈ 2^22 cycles** (~4 million cycles) and proven independently, then linked via global RAM/delegation arguments and recursive compression.
- Multiple machine configurations exist: full ISA, full ISA + delegation, reduced (no signed mul/div), minimal (word-aligned memory only), minimal + delegation, recursion-optimized variants.

Sources:
- `docs/philosophy_and_logic.md` at 73d69b5
- `docs/machine_configuration.md` (main branch)
- `docs/writing_programs.md` at 73d69b5
- `docs/overview.md` (main branch)

## 3. Proof System

- Base proof: **DEEP STARK / FRI** over the **Mersenne31 field** (2^31 − 1).
- Hash function for FRI/commitments: **BLAKE2s / BLAKE3** (not Keccak/SHA2).
- All AIR constraints degree ≤ 2.
- Prover pipeline (per chunk):
  1. Witness LDE + trace commitments
  2. Lookup / memory / delegation arguments
  3. STARK quotient polynomial
  4. DEEP polynomial (FRI batching)
  5. FRI IOPP proof
- **Recursion**: a Rust verifier is compiled to RISC-V and proven recursively; supports `base`, `recursion-unrolled`, `recursion-unified` targets.
- **SNARK / EVM verifier status at commit 73d69b5**:
  - The in-repo end-to-end guide explicitly states: *“Wrapping that artifact into a SNARK is not implemented yet, but it is expected to be supported soon.”*
  - The repository’s own flow ends at a verified Airbender recursive proof artifact; no on-chain verifier is produced.
- Later `main` branch docs describe a Stage 6 “SNARK Wrapper” that wraps the FRI proof into an **FFLONK SNARK** for on-chain verification, using the separate `zkos_wrapper` repo and `era-boojum-validator-cli`. This is **not present** in the pinned commit.

Sources:
- `docs/philosophy_and_logic.md` at 73d69b5
- `docs/end_to_end.md` at 73d69b5
- `docs/overview.md` (main branch) — Stage 6 SNARK wrapper
- <https://docs.zksync.io/zk-stack/components/zksync-airbender>

## 4. Performance & Cycle Counts

- Advertised base-prover throughput:
  - **H100**: ~21.8 MHz (million cycles/sec)
  - **RTX 4090**: ~9.7 MHz
- End-to-end Ethereum block proof: ~35 s on a single H100 (17 s without recursion), per public announcements.
- Chunk size: ~4 million cycles; parallel proving across chunks.
- At pinned commit max program size ≈ 2^30 cycles (~1 billion); main branch raised to ≈ 2^36.
- GPU prover needs ≥ 24 GB VRAM for most work; 32 GB to run final recursion on GPU. CPU backend available.

Sources:
- <https://blockeden.xyz/blog/2026/01/30/zksync-airbender-fastest-risc-v-zkvm-ethereum-proving/>
- <https://zksync.mirror.xyz/ZgRmbYA_EE3wfGcXWv81m-xcED-ppNKkRzkleS6YZRc>
- `docs/end_to_end.md` at 73d69b5
- `docs/tutorial.md` at 73d69b5

## 5. Precompiles / Delegation Circuits

- “Delegation circuits” are precompile-like gadgets triggered via custom CSR `0x7C0` (`CSRRW`).
- **At commit 73d69b5**, implemented delegations:
  - **BLAKE2s / Blake3** round circuits (used for Merkle hashing, recursion commitments).
  - **BigInt / U256** operations: ADD, SUB, MUL_LOW, MUL_HIGH, EQ, CARRY, MEMCOPY on 256-bit values.
    - Used as a primitive for BN254 field arithmetic, secp256k1/secp256r1/BLS12-family curve arithmetic, and modexp.
- **Not available at 73d69b5**:
  - **Keccak256** precompile (added in later dev releases; e.g. release notes mention “dev release used for eth proofs, with keccak precompile”).
  - **SHA-256** precompile.
  - Dedicated **BN254 / BLS12-381 pairing** circuit; only low-level U256 field ops are delegated, so pairing must be built on top or executed in RV32IM.
  - No `ecrecover`, `modexp`, etc. as native delegation circuits.
- Main branch docs still list only Blake2s/Blake3 and U256 BigInt as the core precompiled circuits; later release notes add Keccak.

Sources:
- `docs/delegation_circuits.md` (main branch)
- `docs/philosophy_and_logic.md` at 73d69b5
- `docs/writing_programs.md` at 73d69b5
- GitHub releases: <https://github.com/matter-labs/zksync-airbender/releases>

## 6. License, Maturity, Maintenance

- License: Apache-2.0 or MIT (dual).
- Maintained by **Matter Labs**; very active development.
- Publicly launched June 2025; beta status at launch (“Airbender is still in beta and not production-ready yet”).
- Production intent: replacing Boojum as the proof system for new ZKsync Chains (Abstract, Sophon, GRVT, Lens, Memento) under the Atlas upgrade.
- Professionally audited (audit report referenced in repo).

Sources:
- `README.md` at 73d69b5
- `docs/overview.md` (main branch)
- <https://paragraph.com/@zksync/introducing-zksync-airbender-the-world-s-fastest-open-source-risc-v-zkvm>
- <https://blockeden.xyz/blog/2026/01/30/zksync-airbender-fastest-risc-v-zkvm-ethereum-proving/>

## 7. Production / zkEVM Usage

- Primary use case: proving ZKsync OS state transitions, where ZKsync OS itself is a Rust program compiled to both x86 (sequencer) and RISC-V (prover).
- Used / planned for ZKsync Elastic Network chains, not for Scroll-style multi-tier chunk→batch→bundle zkEVM aggregation.
- No evidence of Airbender being used as the backend for Scroll’s chunk/batch/bundle circuit stack.

Sources:
- `docs/overview.md` (main branch)
- <https://docs.zksync.io/zk-stack/components/zksync-airbender>

## 8. ERE / Interface Notes

- `eth-act/ere` provides a unified Rust API (`Compiler`, `zkVMProver`, `zkVMVerifier`, `Platform`).
- For Airbender:
  - ISA: `RV32IMA`
  - Public-values size limit: **32 bytes** (padded with zeros).
  - Input: length-prefixed `u32` LE stdin; guest reads via nondeterminism CSR path.
  - Supports CPU and GPU proving.
  - ERE lists OpenVM `1.4.3` (note: scroll-zkvm-prover uses OpenVM `1.6`).

Source:
- <https://github.com/eth-act/ere>

## 9. Key Gaps vs. scroll-zkvm-prover Requirements

| Requirement | Airbender at 73d69b5 | Notes |
|-------------|----------------------|-------|
| Multi-tier aggregation (chunk → batch → bundle) | Partial: chunking + recursion for a single program; aggregation of independent chunk proofs requires writing a custom verifier guest | No ready-made “aggregate N app proofs” abstraction like OpenVM’s aggregation layer |
| EVM verifier / SNARK output | **Not implemented** at this commit | Later main branch adds FFLONK SNARK wrapper via external `zkos_wrapper`; pinned commit ends at recursive STARK artifact |
| Keccak precompile | **Missing** at 73d69b5 | Added in later dev releases; essential for zkEVM execution |
| SHA-256 precompile | **Missing** | Can be implemented in software, but costly |
| BN254/BLS12-381 pairing precompile | **Missing** | Only U256 BigInt delegated; pairing must be built from these primitives |
| Large witness inputs | Feasible via nondeterminism CSR / input file; RAM address space 2^30 bytes | Scroll-level witnesses may need careful streaming |
| Public output > 32 bytes | Not directly supported | Must commit to a hash |
