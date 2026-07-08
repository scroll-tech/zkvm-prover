//! Split-process helper for STARK/SNARK proving.
//!
//! Running OpenVM STARK proving and Halo2 SNARK proving in the same process on a
//! 24 GB GPU exhausts VRAM because the parent process already ran chunk/batch
//! STARK proving before the bundle EVM proof. This binary is spawned to generate
//! the bundle EVM proof in a fresh process with a clean CUDA context.

use std::path::PathBuf;

use clap::Parser;
use eyre::Result;
use bincode_v1;
use openvm_circuit::arch::deferral::DeferralState;
use openvm_sdk::DeferralInput;
use scroll_zkvm_prover::{Prover, ProverConfig};
use scroll_zkvm_types::task::ProvingTask as UniversalProvingTask;
use tracing_subscriber::EnvFilter;

use scroll_zkvm_integration::TaskProver;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Parser)]
enum Cmd {
    /// Generate an EVM proof for the final circuit in a fresh process.
    /// The binary loads the full prover chain (chunk -> batch -> bundle) and
    /// enables deferral before running STARK + SNARK proving.
    Evm {
        /// Directory containing the released assets (`chunk/`, `batch/`, `bundle/`, `verifier/`).
        #[arg(long)]
        asset_base_dir: PathBuf,
        /// Target circuit name ("bundle" or "batch").
        #[arg(long)]
        circuit: String,
        /// Path to the serialized [`UniversalProvingTask`].
        #[arg(long)]
        task: PathBuf,
        /// Path to the serialized `Vec<DeferralInput>`.
        #[arg(long)]
        def_inputs: PathBuf,
        /// Path to the serialized `Vec<DeferralState>`.
        #[arg(long)]
        def_states: PathBuf,
        /// Path to write the JSON-encoded [`ProofEnum`].
        #[arg(long)]
        output: PathBuf,
    },
}

fn load_prover(asset_base_dir: &std::path::Path, name: &str) -> Result<Prover> {
    let config = ProverConfig {
        path_app_exe: asset_base_dir.join(name).join("app.vmexe"),
        path_app_config: asset_base_dir.join(name).join("openvm.toml"),
        ..Default::default()
    };
    Ok(Prover::setup(config, Some(name))?)
}

/// Build the prover chain for the target circuit and enable deferral from leaf to root.
/// For "bundle" the chain is chunk -> batch -> bundle.
/// For "batch" the chain is chunk -> batch.
fn build_prover_chain(asset_base_dir: &std::path::Path, circuit: &str) -> Result<Prover> {
    match circuit {
        "bundle" => {
            let chunk_prover = load_prover(asset_base_dir, "chunk")?;
            let mut batch_prover = load_prover(asset_base_dir, "batch")?;
            batch_prover.enable_deferral(&chunk_prover)?;
            let mut bundle_prover = load_prover(asset_base_dir, "bundle")?;
            bundle_prover.enable_deferral(&batch_prover)?;
            Ok(bundle_prover)
        }
        "batch" => {
            let chunk_prover = load_prover(asset_base_dir, "chunk")?;
            let mut batch_prover = load_prover(asset_base_dir, "batch")?;
            batch_prover.enable_deferral(&chunk_prover)?;
            Ok(batch_prover)
        }
        other => eyre::bail!("unsupported circuit for split proving: {other}"),
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Evm {
            asset_base_dir,
            circuit,
            task,
            def_inputs,
            def_states,
            output,
        } => {
            let mut prover = build_prover_chain(&asset_base_dir, &circuit)?;

            let task: UniversalProvingTask = bincode_v1::deserialize(&std::fs::read(&task)?)?;
            let def_inputs: Vec<DeferralInput> =
                bincode_v1::deserialize(&std::fs::read(&def_inputs)?)?;
            let def_states: Vec<DeferralState> =
                bincode_v1::deserialize(&std::fs::read(&def_states)?)?;

            let proof = prover.prove_task_with_deferral(&task, true, &def_inputs, &def_states)?;
            let json = serde_json::to_string(&proof)?;
            std::fs::write(&output, json)?;
        }
    }

    Ok(())
}
