# ZisK zkVM Backend — Agent Notes

This directory is a self-contained Cargo workspace that prototypes **ZisK v1.1.0-alpha** as a
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
- ZisK is **pre-production / unaudited** (v1.1.0-alpha is under security audit). Full GPU
  proving (e.g. the default 6-block chunk workload) is still best-effort, but a
  **single-block chunk proof succeeds on the RTX 4090s** (~59s with v1.1.0-alpha) and
  the guest-side recursion verifier works.

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
  curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/v1.1.0-alpha/ziskup/install.sh \
    | bash -s -- --gpu --nokey -y -v 1.1.0-alpha
  export PATH="$HOME/.zisk/bin:$PATH"
  ```
  `--nokey` is enough for the execution benchmark. To attempt a proof, reinstall with
  `--provingkey` (downloads the STARK proving key + generates constant-tree files), and
  for an EVM Plonk proof also run `ziskup setup_snark` (~36 GB SNARK key).
- **System packages** (new requirements in v1.x — `cargo-zisk` links `libmpi.so.40`;
  `zisk-common` → `proofman` → `mpi-sys` needs MPI headers, `zisk-lib-c` needs `nasm`,
  `proofman-starks-lib-c` compiles CUDA code that includes `gmpxx.h` / `sodium.h` /
  `nlohmann/json.hpp`, the guest-side `zisk-zkvm-interface` runs bindgen on C
  headers, which needs clang, and `ziskemu` needs the OpenMP runtime):
  ```bash
  sudo apt-get install -y libopenmpi3 libopenmpi-dev nasm libgmp-dev nlohmann-json3-dev libsodium-dev clang libclang-dev libomp5
  ```
  `proofman-starks-lib-c` links `-liomp5` (Intel OpenMP name). Ubuntu's `libomp5`
  only ships `libomp.so.5`, so add a dev symlink once:
  ```bash
  sudo ln -sf /lib/x86_64-linux-gnu/libomp.so.5 /usr/lib/x86_64-linux-gnu/libiomp5.so && sudo ldconfig
  ```

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
- On this machine the **ASM backend** (`cargo-zisk prove -a`) times out for small CPU
  proofs. The recursion PoC therefore uses the default Rust emulator (`--emulator`;
  since v1.x the Rust emulator is the default backend — the v0.18 `-l` flag is gone).
- GPU proving of a single-block chunk succeeds with `cargo-zisk prove -g -y` in ~59s
  (v1.1.0-alpha, RTX 4090). The default 6-block workload is much larger and may need a
  longer timeout or flags such as `-c` (minimal) / `-m` (low memory) / `-x <bytes>`
  (witness memory limit) / `--cpu-mops` (fall back to CPU mops planning).
- The batch recursion guest expects the child proof in the format returned by
  `zisk_common::Proof::get_proof_u64()`: `[minimal][n_publics][flag?|program_vk|publics][proof_body][zisk_vk]`.
  Since v1.x a **non-minimal** vadcop_final proof carries a leading
  `is_vadcop_final_proof` public, so `n_publics` is **69** (minimal/compressed stays 68).
  `recursion-test/src/main.rs` splits the trailing 4 u64s as the vkey and frames the rest.
- Since v1.0.0-alpha the default proof hash family is **Poseidon1** (Poseidon2 was
  dropped over https://eprint.iacr.org/2026/306). The in-guest call is
  `verify_vadcop_final_proof(proof, vk, "Poseidon1")` — the hash string must match the
  proving key the child proof was generated with.
- v1.1.0-alpha also ships a **host-side recurser** (`cargo-zisk aggregate`) that folds
  two proofs locally — an official alternative to our in-guest recursion PoC.

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
  The cfg lives in `zisk/.cargo/config.toml`'s `[target.*].rustflags` — since
  v1.1.0-alpha `cargo-zisk build` merges config rustflags into
  `CARGO_ENCODED_RUSTFLAGS` (older versions clobbered `RUSTFLAGS` and ignored the
  config, which is why the cfg used to be injected via the env).

## Version sensitivity

The guest `ziskos` git tag, the installed `cargo-zisk`, and `ziskemu` must be the same
ZisK version. After any ZisK version bump:

1. Reinstall the toolchain **and proving key** (`ziskup -v <version> --gpu --provingkey`
   — keys are versioned and regenerated whenever the constraints change).
2. Rebuild guests with `make build-guest-zisk` and re-check the input framing (the
   length-prefix/alignment convention lives in `ziskos::io`).
3. Delete cached proof artifacts (e.g. `releases/dev/zisk/prover-test/*.bin`) — the
   `zisk-common::Proof` bincode format is not stable across versions.
