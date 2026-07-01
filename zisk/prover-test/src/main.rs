//! ZisK chunk benchmark host (`prove-zisk`).
//!
//! Builds a real Scroll `ChunkWitness` from shared testdata, writes it as a ZisK-framed
//! input file, then runs the ZisK **emulator** (`ziskemu -m`) to measure execution
//! steps/throughput — the key-free, reliable half of the SP1-vs-ZisK comparison. If a
//! proving key is installed it can also attempt a proof via `cargo-zisk prove`.
//!
//! ZisK input framing (see `ziskos::io::read_input_slice`): each value is an 8-byte
//! little-endian length prefix followed by the payload padded up to an 8-byte boundary.

mod witness;

use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Circuit to benchmark (only `chunk` is implemented; batch/bundle are stubs).
    #[arg(long, default_value = "chunk")]
    circuit: String,

    /// Directory containing the compiled ELFs (`<dir>/<circuit>/app`).
    #[arg(long, default_value = "releases/dev/zisk")]
    elf_dir: PathBuf,

    /// Directory to write input/proof artifacts.
    #[arg(long, default_value = "releases/dev/zisk/prover-test")]
    output_dir: PathBuf,

    /// Inclusive block range `start..=end` for the chunk witness (default: preset).
    #[arg(long)]
    block_range: Option<String>,

    /// Path to the `ziskemu` binary.
    #[arg(long, default_value = "ziskemu")]
    ziskemu: String,

    /// Also attempt a proof with `cargo-zisk prove` (requires the proving key).
    #[arg(long)]
    prove: bool,

    /// Use GPU acceleration for proving (`cargo-zisk prove -g`).
    #[arg(long)]
    gpu: bool,

    /// Use the prebuilt emulator for proving (`cargo-zisk prove -l`).
    /// Recommended on this machine because the ASM runner times out for small CPU proofs.
    #[arg(long)]
    emulator: bool,

    /// Path to the `cargo-zisk` binary (used with --prove).
    #[arg(long, default_value = "cargo-zisk")]
    cargo_zisk: String,
}

fn parse_block_range(s: &str) -> eyre::Result<Vec<u64>> {
    let s = s.trim();
    let idx = s
        .find("..")
        .ok_or_else(|| eyre::eyre!("BLOCK_RANGE must be start..=end or start..end"))?;
    let start = s[..idx].trim().parse::<u64>()?;
    let end = if s[idx..].starts_with("..=") {
        s[idx + 3..].trim().parse::<u64>()?
    } else {
        s[idx + 2..].trim().parse::<u64>()?
    };
    Ok((start..=end).collect())
}

/// Frame a payload into ZisK input format: `[u64 LE len][payload][pad to 8 bytes]`.
fn frame_zisk_input(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len() + 7);
    buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    buf
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if args.circuit != "chunk" {
        eyre::bail!(
            "only `chunk` is implemented for ZisK; `{}` is a stub (see zisk/circuits/{}-circuit)",
            args.circuit,
            args.circuit
        );
    }

    std::fs::create_dir_all(&args.output_dir)?;

    // 1. Build the real Scroll chunk witness from shared testdata.
    let block_range = match &args.block_range {
        Some(r) => parse_block_range(r)?,
        None => witness::preset_chunk_block_range(),
    };
    info!("building chunk witness for blocks {:?}", block_range);
    let chunk_witness = witness::build_chunk_witness(block_range.into_iter())?;

    // 2. Encode + frame into a ZisK input file.
    let payload = bincode::serde::encode_to_vec(&chunk_witness, bincode::config::standard())?;
    let framed = frame_zisk_input(&payload);
    let input_path = args.output_dir.join("chunk_input.bin");
    std::fs::write(&input_path, &framed)?;
    info!(
        "wrote ZisK input: {} ({} witness bytes, {} framed bytes)",
        input_path.display(),
        payload.len(),
        framed.len()
    );

    let elf_path = args.elf_dir.join("chunk").join("app");
    if !elf_path.exists() {
        eyre::bail!(
            "chunk ELF not found at {}; run `cargo run -p scroll-zkvm-build-guest-zisk` first",
            elf_path.display()
        );
    }

    // 3. Execute via the emulator (no proving key required) and print metrics.
    info!("running ziskemu execution benchmark on {}", elf_path.display());
    let status = Command::new(&args.ziskemu)
        .arg("-e")
        .arg(&elf_path)
        .arg("-i")
        .arg(&input_path)
        .arg("-m")
        .status()
        .map_err(|e| eyre::eyre!("failed to spawn `{}`: {e}", args.ziskemu))?;
    if !status.success() {
        eyre::bail!("ziskemu execution failed (status {status})");
    }

    // 4. Optional: attempt a proof (requires ~/.zisk/provingKey).
    if args.prove {
        let proof_path = args.output_dir.join("chunk_proof.bin");
        info!("attempting `cargo-zisk prove` (requires proving key)");
        let mut cmd = Command::new(&args.cargo_zisk);
        cmd.arg("prove")
            .arg("-e")
            .arg(&elf_path)
            .arg("-i")
            .arg(&input_path)
            .arg("-o")
            .arg(&proof_path)
            .arg("-y");
        if args.gpu {
            cmd.arg("-g");
        }
        if args.emulator {
            cmd.arg("-l");
        }
        let status = cmd
            .status()
            .map_err(|e| eyre::eyre!("failed to spawn `{}`: {e}", args.cargo_zisk))?;
        if !status.success() {
            eyre::bail!("`cargo-zisk prove` failed (status {status}) — see docs/zisk-backend-assessment.md §4");
        }
        info!("proof written to {}", proof_path.display());
    }

    Ok(())
}
