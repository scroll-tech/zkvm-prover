# Benchmark: SP1 vs ZisK zkVM Backend

> **Scope.** This compares SP1 (v6.3) and ZisK (v0.18.0) as scroll-zkvm-prover backends
> on the **same Scroll chunk workload** (GalileoV2 testdata under
> `crates/integration/testdata`, the blocks the OpenVM/SP1 integration tests use).
>
> Read `docs/zisk-backend-assessment.md` first. The headline constraint: on this
> machine's GPUs, **ZisK full proving historically failed** (documented failures across
> v0.16/0.17 and early 0.18), but **v0.18.0 with the STARK proving key now proves a
> single-block Scroll chunk end-to-end on GPU** and the guest-side recursion verifier
> also works. The 6-block workload is still too slow for a quick run.

## Environment

| Component | Detail |
|-----------|--------|
| Host | Linux, ~128-core, ~1 TB RAM |
| GPUs | 4 × NVIDIA GeForce RTX 3090 (24 GB each), driver 575.57.08 / CUDA 12.9 |
| SP1 | SDK 6.2.2 / guest 6.3.0, `sp1-gpu-server` 6.3.0 |
| ZisK | `cargo-zisk 0.18.0 [gpu]`, `ziskemu` 0.18.0, rust toolchain `zisk` |
| Workload | Scroll chunk, GalileoV2, blocks `20239240..=20239245` (default) and single block `20239240` |

## Methodology

- **Execution** is measured with each zkVM's emulator, which needs no proving key:
  - SP1: `sp1-sdk` `execute()` → `report.total_instruction_count()` (the `prove-sp1`
    host prints `chunk guest executed: N instructions in Xs`).
  - ZisK: `ziskemu -e <chunk.elf> -i <input> -m` → `steps=N ... tp=M Msteps/s`
    (driven by `make bench-zisk-chunk`, which builds a real `ChunkWitness`).
  - Both guests run the **same** logic: deserialize `ChunkWitness` → `ChunkInfo::try_from`
    (stateless block execution via `sbv`/`revm`) → commit the 32-byte `pi_hash`.
    (See "ZisK guest note" below if the ZisK chunk fell back to a reduced guest.)
- **Proving**: SP1 numbers are from `docs/benchmark-sp1-vs-openvm.md` (measured on this
  host, GPU). ZisK proving is reported as attempted/blocked, with the failure evidence.
- Instruction/step counts are **not** directly equal across zkVMs (different ISAs:
  SP1 RV64IMA vs ZisK RV64IMA but different precompiles/lowering, and ZisK counts
  low-level "steps"). Compare *orders of magnitude and wall-clock throughput*, not
  1:1 counts.

## Results — execution (this run)

<!-- RESULTS-EXEC: filled from the current run's `prove-sp1` execute log and `ziskemu -m`. -->
| Backend | Workload | Count | Exec time | Throughput |
|---------|----------|-------|-----------|------------|
| SP1 | chunk, block 20239240 | 565,922,061 instructions | 20.02 s | 28.3 MHz |
| SP1 | chunk, blocks 20239240–45 | 2,725,828,346 instructions | 53.44 s | 51.0 MHz |
| ZisK | chunk, block 20239240 | 604,790,865 steps | 12.05 s | 50.2 Msteps/s |
| ZisK | chunk, blocks 20239240–45 | 3,015,924,765 steps | 60.48 s | 49.9 Msteps/s |

SP1 execution is measured with `CpuProver::execute` (pure emulation) on this host;
SP1 uses accelerated keccak/sha2 (sp1-patches) so these instruction counts already
reflect precompiled crypto. ZisK's chunk guest here uses **software** keccak, so its
step count is not expected to match SP1's instruction count 1:1.

**Correctness cross-check.** Both backends commit the **identical** 32-byte chunk
`pi_hash` for block 20239240 — `0x363c27bd bf063718 cb78963a 44e32f13 b1511066
6fa3fe9c deef1da0 8abc3ca8` — confirming the ZisK guest runs the *same* real Scroll
chunk logic (`ChunkInfo::try_from`, stateless block execution via `revm`) as SP1, not
a stub.

**Reading the numbers.** Work volume is close: ZisK does ~7–10% more steps than SP1
does instructions (604.8M vs 565.9M single-block; 3.016B vs 2.726B for six blocks),
which is the expected penalty for ZisK's software keccak vs SP1's keccak precompile.
Emulator throughput is in the same league — ZisK ~50 Msteps/s (stable), SP1
~28–51 MHz (the single-block figure carries more fixed execute/setup overhead). Neither
side is an order of magnitude ahead on raw execution; the real gap is in **proving**.

## Results — proving (end-to-end capability)

| Backend | Chunk proof | Evidence |
|---------|-------------|----------|
| **SP1** | ✅ single-block compressed **~137 s**; 6-block compressed **~627 s** (GPU, RTX 3090) | `docs/benchmark-sp1-vs-openvm.md` |
| **ZisK** | ✅ single-block full STARK **~100 s** (GPU, RTX 3090, verified with `-y`) | this run, `chunk_proof_gpu_singleblock_default.bin` |
| **ZisK** | ✅ 2-block full STARK **~149 s** (GPU, RTX 3090, verified with `-y`) | this run, `chunk_proof_gpu_2block_default.bin` |
| **ZisK** | ⏳ 6-block full STARK: `-m` low-memory run aborted after >5 min in witness generation | this run |
| **ZisK** | ❌ CPU default path: ASM microservice semaphore `WaitTimeout` | this run |

ZisK's *execute* step is stable, and the **guest-side recursion verifier** also works:
`zisk-verifier::verify_vadcop_final_proof` inside the batch guest verified both the real
single-block and 2-block chunk proofs in ~2 s of `ziskemu` time. The remaining gap for a
full Scroll pipeline is batch/blob validation and the EVM Plonk wrap, not the recursion
primitive.

## Interpretation

1. **SP1 and ZisK both prove 1–2 block Scroll chunks on this hardware.** SP1 is still
   ahead on maturity: its 6-block compressed proof finishes in ~627 s, while ZisK's
   6-block full STARK (even with `-m` low-memory) did not get past witness generation in
   5 min and needs a longer run or a GPU with more memory.
2. **Execution throughput** is a fair, key-free comparison and is reported above. It
   tells us how much raw work each guest does for the same chunk, independent of the
   proving-backend maturity.
3. **ZisK's recursion primitive is functional.** The batch guest successfully verified
   real single-block and 2-block child chunk proofs in-guest. The remaining work for a
   full pipeline is batch/blob validation and EVM wrap, not the core recursion mechanism.
4. ZisK's remaining gaps for a *full* Scroll pipeline (6-block proving stability,
   batch/bundle recursion with real Scroll logic, blob-KZG, EVM Plonk wrap) are tracked
   in `docs/zisk-backend-assessment.md`; only the chunk tier + recursion PoC are wired up.

## Reproduce

```bash
# ZisK toolchain (execution only needs --nokey)
curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh \
  | bash -s -- --gpu --nokey -y -v 0.18.0
export PATH="$HOME/.zisk/bin:$PATH"

# ZisK chunk execution
make build-guest-zisk
make bench-zisk-chunk                 # prints ziskemu steps + Msteps/s
# ZisK single block:
cd zisk && cargo run --release -p scroll-zkvm-zisk-prover-test -- \
  --circuit chunk --block-range 20239240..=20239240

# ZisK chunk proving + recursion PoC (needs `ziskup --provingkey`)
make prove-zisk-chunk                 # attempts a chunk STARK proof (default flags)
make recursion-poc-zisk               # proves bundle stub, verifies it inside batch guest

# Manual recursion with a real chunk proof
cd zisk && cargo run --release -p scroll-zkvm-zisk-recursion-test -- verify-in-guest \
  --proof releases/dev/zisk/prover-test/chunk_proof_gpu_singleblock_default.bin \
  --batch-elf releases/dev/zisk/batch/app

# SP1 chunk execution (instruction count printed before proving; CPU is fine for execute)
cd sp1 && cargo run --release -p scroll-zkvm-sp1-prover-test -- --circuit chunk
```

## ZisK guest note

The **real** ZisK chunk guest compiles — no fallback was needed. The full
`sbv`/`revm`/`reth` stateless-execution graph builds and links for
`riscv64ima-zisk-zkvm-elf`, and the guest commits the same `pi_hash` as SP1 (see the
cross-check above). Two ZisK-specific build fixes were required (both documented in
`zisk/AGENTS.md`):

1. **`cargo-zisk build` clobbers `RUSTFLAGS`**, so `[target.*].rustflags` in
   `.cargo/config.toml` is ignored; the `getrandom_backend="custom"` cfg must be
   injected via the `RUSTFLAGS` env instead (done in `zisk/build-guest`).
2. **getrandom 0.2 vs 0.3 split**: `ziskos` only registers a getrandom-0.2 custom
   backend, but the graph also pulls getrandom 0.3.4, whose custom backend needs an
   external `__getrandom_v03_custom` symbol. The chunk guest provides a small shim
   wired to ziskos' `sys_rand` (the guest only verifies, so this is not
   security-critical; it exists so the graph links).

Software keccak (no `native-keccak`) is used for portability, which is why the ZisK
step counts run slightly higher than SP1's instruction counts.
