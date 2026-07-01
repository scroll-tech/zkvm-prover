# ZisK zkVM Backend — Agent Notes

This directory is a self-contained Cargo workspace that prototypes **ZisK v0.18.0** as a
third zkVM backend for scroll-zkvm-prover, alongside the OpenVM main workspace and the
`sp1/` workspace. Read `docs/zisk-backend-assessment.md` first — it explains why ZisK is
wired in only at the **chunk tier** for now.

## Status (be honest about this)

- **chunk**: real. The guest deserialises a `ChunkWitness`, runs `ChunkInfo::try_from`
  (stateless block execution via `sbv`/`revm`), and commits the 32-byte chunk `pi_hash`.
  Line-for-line equivalent of the SP1 chunk guest.
- **batch**: recursion PoC. The guest imports `zisk-verifier` and calls
  `verify_vadcop_final_proof(proof, vk)` to verify a child ZisK proof in-guest. It has
  been verified end-to-end against both a small bundle-stub child proof and a real
  single-block chunk proof generated on GPU. It does **not** yet implement Scroll batch
  validation (blob-KZG, etc.).
- **bundle**: **stub** (`keccak(input)` placeholder). Real bundle aggregation + EVM Plonk
  wrap is deferred until the batch tier is finished and the ~36 GB SNARK key is available.
- ZisK is **pre-production / unaudited**. Full GPU proving (e.g. the default 6-block chunk
  workload) is still best-effort, but a **single-block chunk proof now succeeds on the
  RTX 3090s** and the guest-side recursion verifier works.

## Quick commands

```bash
# from the repo root
export PATH="$HOME/.zisk/bin:$PATH"

# 1. Build the ZisK guest ELFs -> zisk/releases/dev/zisk/{chunk,batch,bundle}/app
make build-guest-zisk

# 2. Run the chunk execution benchmark (builds a real witness, runs ziskemu -m)
make bench-zisk-chunk

# 3. Attempt a single-block chunk STARK proof on GPU (needs ziskup --provingkey)
make prove-zisk-chunk      # default 6-block workload; for single block use --block-range

# 4. In-guest recursion PoC: prove bundle stub, verify inside batch guest
make recursion-poc-zisk
```

## Workspace layout

- `circuits/{chunk,batch,bundle}-circuit/` — ZisK guests (`ziskos::entrypoint!`).
- `build-guest/` — host binary that drives `cargo-zisk build` and copies ELFs to
  `releases/dev/zisk/{circuit}/app`.
- `prover-test/` — host binary `prove-zisk`: builds the chunk witness, writes a
  ZisK-framed input file, runs `ziskemu -m`, and optionally `cargo-zisk prove`.
  Deliberately does **not** depend on `ziskos` (guest-only) or the heavy `zisk-sdk`.
  Use `--prove --gpu` for GPU proving or `--prove --emulator` for the prebuilt emulator
  (recommended on this machine for CPU).
- `recursion-test/` — host binary `recursion-test`: drives the in-guest recursion PoC.
  Depends on `zisk-common` to load child proofs and frame the batch-guest input.

## ZisK prerequisites

- ZisK toolchain installed via `ziskup`:
  ```bash
  curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh \
    | bash -s -- --gpu --nokey -y -v 0.18.0
  export PATH="$HOME/.zisk/bin:$PATH"
  ```
  `--nokey` is enough for the execution benchmark. To attempt a proof, reinstall with
  `--provingkey` (downloads the STARK proving key + generates constant-tree files), and
  for an EVM Plonk proof also run `ziskup setup_snark` (~36 GB SNARK key).

## Guest I/O contract

- Host writes the input file as ZisK-framed bytes: `[u64 LE len][payload][pad to 8]`.
  The chunk payload is `bincode::config::standard()` of a `ChunkWitness`.
- Guest reads with `ziskos::io::read_input_slice()` and commits with
  `ziskos::io::commit_slice(&pi_hash)`.

## Proving notes

- `cargo-zisk prove -i <file>` passes the file bytes straight to the guest. Because our
  guests use `ziskos::io::read_input_slice()`, the file must be **ZisK-framed** and its
  total length a multiple of 8. The chunk benchmark already writes such a file; for the
  recursion PoC we frame the bundle-stub input inline in the Makefile.
- On this machine the default **ASM runner** (`cargo-zisk prove` without `-l`) times out
  for small CPU proofs. The recursion PoC therefore uses `-l` (prebuilt emulator) for the
  child proof.
- GPU proving of a single-block chunk succeeds with `cargo-zisk prove -g -y` in ~100s.
  The default 6-block workload is much larger and may need a longer timeout or flags such
  as `-c` (minimal) / `-m` (low memory) / `-x <bytes>` (witness memory limit).
- The batch recursion guest expects the child proof in the format returned by
  `zisk_common::Proof::get_proof_u64()`: `[minimal][n_publics][program_vk][publics][proof_body][zisk_vk]`.
  `recursion-test/src/main.rs` splits the trailing 4 u64s as the vkey and frames the rest.

## Dependency notes

- Guests reuse the backend-agnostic `scroll-zkvm-types-*` crates from the main
  workspace (no `openvm` feature). The workspace pins the same `scroll-tech/revm`
  (`scroll-v91`) patch as the main + `sp1/` workspaces so `sbv-*` resolves one revm.
- Guests use **software keccak** (no `native-keccak`) to keep the build portable; this
  gives up ZisK's keccak syscall acceleration (more steps, still correct).
- **getrandom**: the sbv/revm graph pulls **two** getrandom majors. getrandom **0.2**
  (via `rand` 0.8) is handled by ziskos' `register_custom_getrandom!` backend. getrandom
  **0.3.x** needs the `getrandom_backend="custom"` cfg *and* an external
  `__getrandom_v03_custom` symbol — ziskos does **not** register the 0.3 backend, so the
  chunk guest defines that symbol itself (wired to ziskos' `sys_rand`; see
  `circuits/chunk-circuit/src/main.rs`) and depends on `getrandom` 0.3 to name the type.
  The cfg is injected via the `RUSTFLAGS` env in `build-guest/src/main.rs` because
  `cargo-zisk build` sets `RUSTFLAGS` itself and thereby ignores `.cargo/config.toml`'s
  `[target.*].rustflags` (see the note in that file).

## Version sensitivity

The guest `ziskos` git tag, the installed `cargo-zisk`, and `ziskemu` must be the same
ZisK version. After any ZisK version bump, rebuild guests with `make build-guest-zisk`
and re-check the input framing (the length-prefix/alignment convention lives in
`ziskos::io`).
