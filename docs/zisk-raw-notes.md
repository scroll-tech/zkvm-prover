# ZisK zkVM (≈ v0.18.0) raw research notes

Research target: ZisK zkVM as pinned by `eth-act/ere` at `v0.18.0`, for possible use in a Scroll-style multi-tier zkEVM prover (`scroll-zkvm-prover`, currently OpenVM v1.6).

---

## 1. Architecture & ISA

- **ISA**: RISC-V 64-bit (`RV64IMA`), target triple `riscv64ima-zisk-zkvm-elf`.  
  Source: ZisK docs quickstart, `ere` catalog, Nethereum README.
- **Guest languages**: Rust primary; C/C++, Go, .NET/NativeAOT, Zig also supported experimentally (v0.18.0 fixes unaligned access/NativeAOT).
- **Execution modes**:
  - Software emulator (`ziskemu`).
  - Native assembly executor (`--asm`, Linux x86_64).
  - CUDA GPU executor (`--gpu`).
  - `--asm` and `--gpu` can be combined.
- **Continuation / large programs**:
  - Step limit raised to **2³⁶ steps (64 Gigasteps)** in v0.18.0.
  - Ethereum block analysis (22k+ mainnet blocks): peak ~950 Msteps, average ~310 Msteps.
  - Supports **distributed proving**: coordinator + worker fleet, MPI, gRPC hints/inputs streaming, QUIC, Unix sockets.
- **Program setup**: per-guest-binary setup key (`cargo-zisk setup`). The setup encodes the program structure / trace shape.

---

## 2. Proof system

- **Base proof**: STARK over execution trace, built on Polygon’s **PIL2** constraint language and **Proofman** prover backend. Uses **Plonky3** technology and FRI-style polynomial commitments.
  - Source: ZisK README acknowledgements, release notes, docs.
- **Proof formats (CLI)**:
  - Default: STARK proof (off-chain verification).
  - `--minimal`: smaller STARK, longer proving time.
  - `--plonk`: PLONK SNARK wrapper for EVM on-chain verification.
- **Recursion / aggregation**:
  - v0.18.0 release notes: “Proofs can now be verified in a separate guest program, allowing zisk proofs aggregation.”
  - Earlier v0.11.0 note: “recursive circuits migrated to PIL2”.
  - This is a *guest-level* verifier, not a separate fixed recursive circuit like RISC Zero’s recursion circuit or OpenVM’s `root_verifier.asm`.

---

## 3. EVM verifier / SNARK wrapper

- **GPU Plonk SNARK wrapper** added in v0.18.0:
  - Proof size: ~1 KB.
  - Estimated verification cost: ~250k gas.
  - Wrapper generation: <2 seconds.
- CLI: `cargo-zisk prove ... --plonk` produces the EVM-verifiable proof.
- Requires a **PLONK proving key** (~36 GB, installed by `ziskup plonk` or downloaded separately).
- Solidity verifier exists and was updated in v0.18.0.
  - Source: ZisK GitHub releases page, quickstart docs.

---

## 4. Precompiles / accelerators

ZisK exposes accelerators via **RISC-V CSR instructions** (single instruction `csrs <CSR>, a0`) or `ecall` syscalls. The current list (from docs + Nethereum reverse-engineering) is:

- **Arithmetic**: `add256`, `arith256`, `arith256_mod`, `arith384_mod`.
- **Hashes**: `keccak_f`, `sha256_f`, `blake2b_round`, `poseidon2`.
- **Elliptic curves**:
  - secp256k1: add, dbl.
  - secp256r1: add, dbl, ECDSA verify.
  - BN254: G1 add/dbl, Fp2 complex add/sub/mul.
  - BLS12-381: G1 add/dbl, Fp2 complex add/sub/mul, `fp_to_g1`, `fp2_to_g2`.
- **DMA/memory**: `memcpy`, `memcmp`, `memset`, `inputcpy` (v0.18.0 DMA precompile, 20–35% step reduction).

### Important nuance for zkEVM precompiles

There is **no dedicated `bn254_pairing_check` or `bls12_381_pairing_check` CSR**.  Instead, higher-level Ethereum precompiles are implemented in `libziskos.a` as Rust orchestration over the low-level field/curve CSR ops:

| EVM precompile | ZisK implementation |
|----------------|---------------------|
| `ECRECOVER` | `secp256k1_ecdsa_address_recover_c` |
| `SHA-256` | `sha256_c` |
| `MODEXP` | `modexp_bytes_c` (uses `arith256_mod`) |
| `BN254 ADD/MUL` | `bn254_g1_add_c` / `bn254_g1_mul_c` |
| `BN254 PAIRING` | `bn254_pairing_check_c` (Miller loop + final exp built from `bn254_curve_add/dbl`, `bn254_complex_*`, `arith256_mod`) |
| `KZG` | `verify_kzg_proof_c` (uses BLS12-381 ops) |
| `BLS12-381` | built from BLS12-381 curve/complex ops + `arith384_mod` |

Source: Nethereum EVM → Zisk README (`github.com/nethereum/nethereum/blob/master/zisk/README.md`).

This means pairing is *possible* but not a single native accelerator; it will cost more cycles than a dedicated pairing precompile (cf. SP1 reports ~155M → ~6.6M cycles for `alt_bn128_pair` with a native precompile).

---

## 5. Performance / cycle count

- Claimed **1.5 GHz zkVM execution** and real-time Ethereum block proving.
- v0.18.0 Ethereum-block analysis: average ~310 Msteps, peak ~950 Msteps for mainnet blocks.
- Step limit 2³⁶ ≈ 64 Gsteps should accommodate very large programs.
- No published RTP (Real-Time Proving) metrics on ETHProofs for ZisK as of research date; industry reviews place ZisK in the “second tier” with RISC Zero/ZKM, behind SP1/Pico.
- Quickstart hash example: ~19k steps, CPU proof ~147s.

---

## 6. License, maturity, maintenance

- **License**: dual Apache-2.0 / MIT.
- **Origin**: incubated at Polygon Labs (May 2024 – June 2025), then spun out to **SilentSig Switzerland GmbH** (Jordi Baylina) on 2025-06-13.
- **Team**: ~7 core developers from Polygon zkEVM / Hermez.
- **Maturity**: explicit disclaimer on every release page:
  - “active development”, not audited, not fully tested, “do not use in production until a stable release”.
  - Breaking backward-compatible changes expected.
  - macOS not supported as of v0.18.0.
- **Maintenance**: very active (v0.18.0 released recently at time of research).

---

## 7. Known production / ecosystem usage

- **zisk-eth-client** – experimental stateless Ethereum execution client built on Reth.
- **davinci-zkvm** – Vocdoni voting protocol circuit (does Groth16 batch verify, ECDSA, SMT, KZG, etc.).
- **Nethereum EVM → Zisk** – C# EVM compiled to RISC-V and proven in ZisK.
- **Venus / Cysic Labs** – hardware-accelerated fork of ZisK (FPGA/ASIC).
- **ETHProofs** – ZisK listed as an RTP participant; in-browser verifier announced.
- **No known production zkEVM/rollup** running live with ZisK as the proving backend today.

---

## 8. I/O, public values, witness handling

- **Inputs**: 1 GB persistent input stream (v0.18.0); compatible with `zerocopy` and `bincode`; supports progressive/pipelined loading.
- **Hints**: streaming architecture (`--hints-stream`) with built-in handlers for BN254/BLS12-381 pairing, KZG, MODEXP, hashing, ECDSA.
- **Public outputs**: ZisK public-values buffer is **256 bytes** (per `eth-act/ere` comparison table). Scroll-style circuits hash public inputs to 32 bytes, so this is not a hard blocker, but the aggregation flow must fit within it.

---

## 9. Comparison points relevant to scroll-zkvm-prover

| Need | OpenVM v1.6 (current) | ZisK v0.18.0 |
|------|----------------------|--------------|
| ISA | RV32IMA | RV64IMA |
| Base proof | STARK (Plonky3 / GKR) | STARK (PIL2 / Proofman / Plonky3) |
| EVM SNARK | Halo2-KZG wrapper | GPU Plonk wrapper (~250k gas, ~1KB) |
| Aggregation | `root_verifier.asm` / native recursive verifier | Guest-level proof verification; “proofs can be verified in a separate guest program” |
| Chunk precompiles (keccak, sha256, BN254 ecc+pairing, secp256k1, P256) | Native intrinsic precompiles | Low-level BN254/secp256k1/secp256r1 ops; **pairing is composed, not a single precompile** |
| Batch precompiles (BLS12-381 ecc+pairing) | Native intrinsic precompiles | Low-level BLS12-381 ops; pairing composed |
| Bundle | mostly keccak/sha256 | keccak/sha256 fine |
| Large witness input | stdin / hints | 1 GB input stream + streaming hints |
| Public outputs | 32 bytes (padded) | 256 bytes |
| Setup | universal-ish + SRS | per-program setup key + ~36 GB PLONK key |
| Production readiness | Scroll already shipping integration | Pre-production, not audited |

---

## 10. Key sources

- ZisK main repo: https://github.com/0xPolygonHermez/zisk
- ZisK releases / v0.18.0 notes: https://github.com/0xPolygonHermez/zisk/releases
- ZisK docs landing: https://0xpolygonhermez.github.io/zisk-docs/
- ZisK quickstart (proof formats, CLI): https://0xpolygonhermez.github.io/zisk-docs/developer/getting-started/quickstart
- Precompiles docs: https://0xpolygonhermez.github.io/zisk/getting_started/precompiles.html
- `eth-act/ere` zkVM catalog: https://github.com/eth-act/ere (pins ZisK 0.18.0)
- Nethereum EVM → ZisK README (CSR/precompile mapping): https://github.com/nethereum/nethereum/blob/master/zisk/README.md
- ZisK Ethereum client: https://github.com/0xPolygonHermez/zisk-eth-client
- Davinci ZisK circuit: https://github.com/vocdoni/davinci-zkvm
- Venus/Cysic fork: https://github.com/cysic-labs/venus
- zkEVM benchmark workload: https://github.com/eth-act/zkevm-benchmark-workload
