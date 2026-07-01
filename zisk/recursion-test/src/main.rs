//! ZisK in-guest recursion PoC host driver.
//!
//! Two-step workflow:
//!
//! 1. `prove-child` — call `cargo-zisk prove` to generate a STARK proof for a small
//!    child ELF. On this machine the ASM runner times out for small CPU proofs, so the
//!    Makefile uses `--minimal --emulator` (`-c -l`) for the bundle-stub child proof.
//!
//! 2. `verify-in-guest` — load the child `Proof`, serialize it into the shape expected by
//!    the batch recursion guest (`[proof][vk]`), frame it, and run `ziskemu` on the batch
//!    ELF.  The batch guest returns a 32-byte value whose first byte is `1` iff the child
//!    proof verified in-guest.

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};
use tracing::info;
use zisk_common::Proof;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Prove a small child ELF with `cargo-zisk prove`.
    ProveChild {
        /// Child ELF path.
        #[arg(long)]
        elf: PathBuf,
        /// Child input file. For guests using `ziskos::io::read_input_slice()` this must be
        /// the ZisK-framed input ( `[u64 LE len][payload][pad to 8]` ), which is what
        /// `prove-zisk` writes.
        #[arg(long)]
        input: PathBuf,
        /// Where to write the bincode-encoded `Proof`.
        #[arg(long)]
        output: PathBuf,
        /// Generate a minimal (compressed) STARK proof.
        #[arg(long)]
        minimal: bool,
        /// Use the prebuilt emulator (`-l`) instead of the ASM runner.
        #[arg(long)]
        emulator: bool,
        /// Use GPU acceleration (`-g`).
        #[arg(long)]
        gpu: bool,
        /// `cargo-zisk` binary.
        #[arg(long, default_value = "cargo-zisk")]
        cargo_zisk: String,
    },
    /// Feed a child proof into the batch recursion guest and run it in ziskemu.
    VerifyInGuest {
        /// Child proof file produced by `prove-child`.
        #[arg(long)]
        proof: PathBuf,
        /// Batch recursion ELF.
        #[arg(long)]
        batch_elf: PathBuf,
        /// Directory for framed input / output files.
        #[arg(long, default_value = "releases/dev/zisk/prover-test")]
        work_dir: PathBuf,
        /// `ziskemu` binary.
        #[arg(long, default_value = "ziskemu")]
        ziskemu: String,
    },
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

fn prove_child(
    elf: &Path,
    input: &Path,
    output: &Path,
    minimal: bool,
    emulator: bool,
    gpu: bool,
    cargo_zisk: &str,
) -> eyre::Result<()> {
    info!("proving child ELF {}", elf.display());
    let mut cmd = Command::new(cargo_zisk);
    cmd.arg("prove")
        .arg("-e")
        .arg(elf)
        .arg("-i")
        .arg(input)
        .arg("-o")
        .arg(output)
        .arg("-y"); // verify after generation
    if minimal {
        cmd.arg("-c");
    }
    if emulator {
        cmd.arg("-l");
    }
    if gpu {
        cmd.arg("-g");
    }
    let status = cmd
        .status()
        .map_err(|e| eyre::eyre!("failed to spawn `{cargo_zisk} prove`: {e}"))?;
    if !status.success() {
        eyre::bail!("`{cargo_zisk} prove` failed (status {status})");
    }
    info!("child proof saved to {}", output.display());
    Ok(())
}

fn verify_in_guest(
    proof_path: &Path,
    batch_elf: &Path,
    work_dir: &Path,
    ziskemu: &str,
) -> eyre::Result<()> {
    info!("loading child proof from {}", proof_path.display());
    let proof = Proof::load(proof_path)
        .map_err(|e| eyre::eyre!("failed to load ZisK proof: {e}"))?;

    // get_proof_u64 returns: [minimal(1)][n_publics(1)][program_vk][publics][proof_body][zisk_vk]
    // The batch guest's verify_vadcop_final_proof expects proof without vk and vk separately.
    let words = proof
        .get_proof_u64()
        .map_err(|e| eyre::eyre!("failed to serialize proof as u64 words: {e}"))?;
    if words.len() < 4 {
        eyre::bail!("proof too short: {} words", words.len());
    }
    let (proof_words, vk_words) = words.split_at(words.len() - 4);
    assert_eq!(vk_words.len(), 4, "zisk vk must be 4 u64s");

    // Batch guest framing: [proof_len][proof words...][vk_len][vk words...]
    let mut payload = Vec::with_capacity((1 + proof_words.len() + 1 + vk_words.len()) * 8);
    payload.extend_from_slice(&(proof_words.len() as u64).to_le_bytes());
    for w in proof_words {
        payload.extend_from_slice(&w.to_le_bytes());
    }
    payload.extend_from_slice(&(vk_words.len() as u64).to_le_bytes());
    for w in vk_words {
        payload.extend_from_slice(&w.to_le_bytes());
    }

    std::fs::create_dir_all(work_dir)?;
    let input_path = work_dir.join("batch_input_child_proof.bin");
    let output_path = work_dir.join("batch_output_child_proof.bin");
    std::fs::write(&input_path, &frame_zisk_input(&payload))?;
    info!(
        "framed batch input: {} ({} u64 words of proof + {} u64 words of vk)",
        input_path.display(),
        proof_words.len(),
        vk_words.len()
    );

    info!("running batch recursion guest {}", batch_elf.display());
    let status = Command::new(ziskemu)
        .arg("-e")
        .arg(batch_elf)
        .arg("-i")
        .arg(&input_path)
        .arg("-o")
        .arg(&output_path)
        .status()
        .map_err(|e| eyre::eyre!("failed to spawn `{ziskemu}`: {e}"))?;
    if !status.success() {
        eyre::bail!("`{ziskemu}` failed (status {status})");
    }

    let out = std::fs::read(&output_path)?;
    if out.is_empty() {
        eyre::bail!("batch guest produced no output");
    }
    let verified = out[0] == 1;
    info!(
        "in-guest verification result: {} (output file: {})",
        if verified { "VERIFIED" } else { "REJECTED" },
        output_path.display()
    );

    if !verified {
        // This is expected if the child proof is malformed, minimal-vs-full mismatch,
        // or if the publics in the proof do not match what the verifier recomputes.
        eyre::bail!("child proof was rejected by the batch recursion guest");
    }
    Ok(())
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    match args.command {
        Cmd::ProveChild { elf, input, output, minimal, emulator, gpu, cargo_zisk } => {
            prove_child(&elf, &input, &output, minimal, emulator, gpu, &cargo_zisk,
            )?;
        }
        Cmd::VerifyInGuest { proof, batch_elf, work_dir, ziskemu } => {
            verify_in_guest(&proof, &batch_elf, &work_dir, &ziskemu)?;
        }
    }
    Ok(())
}
