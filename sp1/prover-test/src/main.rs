mod witness;

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use eyre::Context;
use sp1_hypercube::{SP1PcsProofInner, SP1RecursionProof};
use sp1_primitives::SP1GlobalContext;
use sp1_sdk::{
    CpuProver, Elf, HashableKey, Prover, ProveRequest, ProvingKey, SP1Proof,
    SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use sp1_sdk::cuda::builder::CudaProverBuilder;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Circuit to prove (chunk, batch, bundle).
    #[arg(long, default_value = "chunk")]
    circuit: String,

    /// Use the CUDA prover on the GPU selected by CUDA_VISIBLE_DEVICES.
    #[arg(long)]
    gpu: bool,

    /// CUDA device id to use when --gpu is set (defaults to CUDA_VISIBLE_DEVICES or 0).
    #[arg(long)]
    device_id: Option<u32>,

    /// Directory containing the compiled ELF.
    #[arg(long, default_value = "releases/dev/sp1")]
    elf_dir: PathBuf,

    /// Directory to write proof artifacts.
    #[arg(long, default_value = "releases/dev/sp1/prover-test")]
    output_dir: PathBuf,
}

/// Execute the guest once to get an instruction count and sanity-check the inputs.
async fn execute_guest<P: Prover>(
    client: &P,
    elf: &'static [u8],
    stdin: &SP1Stdin,
    label: &str,
) -> eyre::Result<u64>
where
    P::Error: std::error::Error + Send + Sync + 'static,
{
    let start = Instant::now();
    let (public_values, report) = client
        .execute(Elf::Static(elf), stdin.clone())
        .deferred_proof_verification(false)
        .await
        .map_err(|e| eyre::eyre!("{label} guest execution failed: {e:?}"))?;
    let instructions = report.total_instruction_count();
    info!(
        "{label} guest executed: {instructions} instructions in {:.2}s",
        start.elapsed().as_secs_f64()
    );
    info!("{label} public values: {:?}", public_values);
    Ok(instructions)
}

/// Log proving speed in MHz, matching the style used by the OpenVM integration logs.
fn log_proof_speed(label: &str, instructions: u64, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    let mhz = if secs > 0.0 {
        instructions as f64 / secs / 1_000_000.0
    } else {
        0.0
    };
    info!(
        "{label} proof: {instructions} instructions in {secs:.2}s ({mhz:.2} MHz)",
    );
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    std::fs::create_dir_all(&args.output_dir)?;

    let device_id = args.device_id.unwrap_or_else(|| {
        std::env::var("CUDA_VISIBLE_DEVICES")
            .ok()
            .and_then(|s| s.split(',').next().map(|x| x.parse().ok()).flatten())
            .unwrap_or(0)
    });

    if args.gpu {
        info!("using CUDA prover on device {device_id}");
        let client = CudaProverBuilder::default()
            .with_device_id(device_id)
            .build()
            .await;
        run_circuit(&client, &args).await?;
    } else {
        info!("using CPU prover");
        let client = CpuProver::new().await;
        run_circuit(&client, &args).await?;
    }

    info!("all done");
    Ok(())
}

async fn run_circuit<P: Prover>(client: &P, args: &Args) -> eyre::Result<()>
where
    P::Error: std::error::Error + Send + Sync + 'static,
{
    match args.circuit.as_str() {
        "chunk" => prove_chunk(client, args).await,
        "batch" => prove_batch(client, args).await,
        "bundle" => prove_bundle(client, args).await,
        other => eyre::bail!("unknown circuit: {other}"),
    }
}

async fn prove_chunk<P: Prover>(client: &P, args: &Args) -> eyre::Result<()>
where
    P::Error: std::error::Error + Send + Sync + 'static,
{
    let elf = load_elf(args, "chunk")?;
    let mut stdin = SP1Stdin::new();

    // Build a real Scroll chunk witness from shared testdata.
    let block_range = if let Ok(r) = std::env::var("BLOCK_RANGE") {
        let r = r.trim();
        if let Some(idx) = r.find("..") {
            let start = r[..idx].trim().parse::<u64>()?;
            let end = if r[idx..].starts_with("..=") {
                r[idx + 3..].trim().parse::<u64>()?
            } else {
                // start..end means inclusive end for our purposes.
                r[idx + 2..].trim().parse::<u64>()?
            };
            (start..=end).collect()
        } else {
            eyre::bail!("BLOCK_RANGE must be start..=end or start..end");
        }
    } else {
        witness::preset_chunk_block_range()
    };
    info!("building chunk witness for blocks {:?}", block_range);
    let chunk_witness = witness::build_chunk_witness(block_range.into_iter())?;
    let witness_bytes = bincode::serde::encode_to_vec(&chunk_witness, bincode::config::standard())?;
    stdin.write_vec(witness_bytes);

    let pk = client.setup(Elf::Static(elf)).await?;
    let vk = pk.verifying_key();
    info!("chunk vkey hash: {}", vk.bytes32());

    let instructions = execute_guest(client, elf, &stdin, "chunk").await?;

    // Compressed proof is required for recursive aggregation in batch/bundle.
    info!("generating chunk compressed proof");
    let start = Instant::now();
    let compressed = client.prove(&pk, stdin).compressed().await?;
    log_proof_speed("chunk compressed", instructions, start.elapsed());
    client.verify(&compressed, vk, None)?;
    info!("chunk compressed proof verified");

    save_proof(&compressed, args, "chunk", "compressed")?;
    save_vk(vk, args, "chunk")?;

    Ok(())
}

async fn prove_child<P: Prover>(
    client: &P,
    args: &Args,
    circuit: &str,
    stdin: SP1Stdin,
) -> eyre::Result<(SP1ProofWithPublicValues, SP1VerifyingKey)>
where
    P::Error: std::error::Error + Send + Sync + 'static,
{
    let elf = load_elf(args, circuit)?;
    let pk = client.setup(Elf::Static(elf)).await?;
    let vk = pk.verifying_key();
    info!("{circuit} vkey hash: {}", vk.bytes32());

    let instructions = execute_guest(client, elf, &stdin, circuit).await?;

    info!("generating {circuit} compressed proof");
    let start = Instant::now();
    let compressed = client.prove(&pk, stdin).compressed().await?;
    log_proof_speed(&format!("{circuit} compressed"), instructions, start.elapsed());
    client.verify(&compressed, vk, None)?;
    info!("{circuit} compressed proof verified");

    Ok((compressed, vk.clone()))
}

async fn prove_batch<P: Prover>(client: &P, args: &Args) -> eyre::Result<()>
where
    P::Error: std::error::Error + Send + Sync + 'static,
{
    // Build and prove the child chunks that make up this batch.
    let chunk_ranges = witness::preset_batch_chunk_ranges();
    info!("batch will aggregate chunks for block ranges {:?}", chunk_ranges);

    let mut chunk_proofs = Vec::new();
    let mut chunk_vks = Vec::new();
    for (idx, range) in chunk_ranges.into_iter().enumerate() {
        info!("proving chunk {} for blocks {:?}", idx, range);
        let chunk_witness = witness::build_chunk_witness(range.into_iter())?;
        let mut stdin = SP1Stdin::new();
        let witness_bytes =
            bincode::serde::encode_to_vec(&chunk_witness, bincode::config::standard())?;
        stdin.write_vec(witness_bytes);
        let (proof, vk) = prove_child(client, args, "chunk", stdin).await?;
        chunk_proofs.push(proof);
        chunk_vks.push(vk);
    }

    // Build the real Scroll batch witness from the child chunks.
    let chunk_witnesses: Vec<_> = {
        let ranges = witness::preset_batch_chunk_ranges();
        ranges
            .into_iter()
            .map(|r| witness::build_chunk_witness(r.into_iter()))
            .collect::<eyre::Result<Vec<_>>>()?
    };
    let batch_witness = witness::build_batch_witness(&chunk_witnesses)?;
    let batch_witness_bytes =
        bincode::serde::encode_to_vec(&batch_witness, bincode::config::standard())?;

    // Assemble the batch stdin: digests first, then proofs via write_proof, then the witness.
    let elf = load_elf(args, "batch")?;
    let mut stdin = SP1Stdin::new();
    let num_chunks: u32 = chunk_proofs.len() as u32;
    stdin.write(&num_chunks);
    for (proof, vk) in chunk_proofs.iter().zip(chunk_vks.iter()) {
        let vk_digest = vk.hash_u32();
        let pv_digest: [u8; 32] = proof.public_values.hash().try_into().map_err(|_| {
            eyre::eyre!("chunk public values digest is not 32 bytes")
        })?;
        stdin.write(&vk_digest);
        stdin.write(&pv_digest);
    }
    for (proof, vk) in chunk_proofs.iter().zip(chunk_vks.iter()) {
        let recursion_proof = extract_recursion_proof(proof)?;
        stdin.write_proof(recursion_proof, vk.vk.clone());
    }
    stdin.write_vec(batch_witness_bytes);

    let pk = client.setup(Elf::Static(elf)).await?;
    let vk = pk.verifying_key();
    info!("batch vkey hash: {}", vk.bytes32());

    let instructions = execute_guest(client, elf, &stdin, "batch").await?;

    info!("generating batch compressed proof");
    let start = Instant::now();
    let compressed = client.prove(&pk, stdin).compressed().await?;
    log_proof_speed("batch compressed", instructions, start.elapsed());
    client.verify(&compressed, vk, None)?;
    info!("batch compressed proof verified");

    save_proof(&compressed, args, "batch", "compressed")?;
    save_vk(vk, args, "batch")?;

    Ok(())
}

async fn prove_bundle<P: Prover>(client: &P, args: &Args) -> eyre::Result<()>
where
    P::Error: std::error::Error + Send + Sync + 'static,
{
    // Load the batch proof to aggregate.
    let batch_proof = load_proof(args, "batch", "compressed")
        .context("failed to load batch compressed proof; run `prove-sp1 --circuit batch` first")?;
    let batch_vk = load_vk(args, "batch")?;

    // Build the bundle witness from the same batch configuration used above.
    let batch_witnesses = witness::preset_batch_witnesses()?;
    let bundle_witness = witness::build_bundle_witness(&batch_witnesses)?;
    let bundle_witness_bytes =
        bincode::serde::encode_to_vec(&bundle_witness, bincode::config::standard())?;

    let elf = load_elf(args, "bundle")?;
    let mut stdin = SP1Stdin::new();

    let num_batches: u32 = 1;
    stdin.write(&num_batches);

    let vk_digest = batch_vk.hash_u32();
    let pv_digest: [u8; 32] = batch_proof.public_values.hash().try_into().map_err(|_| {
        eyre::eyre!("batch public values digest is not 32 bytes")
    })?;
    stdin.write(&vk_digest);
    stdin.write(&pv_digest);

    let recursion_proof = extract_recursion_proof(&batch_proof)?;
    stdin.write_proof(recursion_proof, batch_vk.vk.clone());
    stdin.write_vec(bundle_witness_bytes);

    let pk = client.setup(Elf::Static(elf)).await?;
    let vk = pk.verifying_key();
    info!("bundle vkey hash: {}", vk.bytes32());

    let instructions = execute_guest(client, elf, &stdin, "bundle").await?;

    info!("generating bundle Plonk proof");
    let start = Instant::now();
    let plonk = client.prove(&pk, stdin).plonk().await?;
    log_proof_speed("bundle Plonk", instructions, start.elapsed());
    client.verify(&plonk, vk, None)?;
    info!("bundle Plonk proof verified");

    save_proof(&plonk, args, "bundle", "plonk")?;
    save_vk(vk, args, "bundle")?;
    save_bundle_artifacts(&plonk, args)?;

    Ok(())
}

fn load_elf(args: &Args, circuit: &str) -> eyre::Result<&'static [u8]> {
    let path = args.elf_dir.join(circuit).join("app");
    info!("loading {circuit} ELF from {}", path.display());
    let elf = std::fs::read(&path)?;
    Ok(Box::leak(elf.into_boxed_slice()))
}

fn load_proof(args: &Args, circuit: &str, kind: &str) -> eyre::Result<SP1ProofWithPublicValues> {
    let path = args.output_dir.join(format!("{circuit}_{kind}_proof.bin"));
    info!("loading {circuit} {kind} proof from {}", path.display());
    SP1ProofWithPublicValues::load(&path)
        .map_err(|e| eyre::eyre!("failed to load {circuit} {kind} proof: {e}"))
}

fn load_vk(args: &Args, circuit: &str) -> eyre::Result<SP1VerifyingKey> {
    let path = args.output_dir.join(format!("{circuit}_vk.bin"));
    info!("loading {circuit} vk from {}", path.display());
    let bytes = std::fs::read(&path)?;
    Ok(bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?.0)
}

fn save_proof(
    proof: &SP1ProofWithPublicValues,
    args: &Args,
    circuit: &str,
    kind: &str,
) -> eyre::Result<()> {
    let path = args.output_dir.join(format!("{circuit}_{kind}_proof.bin"));
    proof.save(&path).map_err(|e| eyre::eyre!("failed to save {circuit} {kind} proof: {e}"))?;
    info!("saved {circuit} {kind} proof to {}", path.display());
    Ok(())
}

fn save_vk(vk: &SP1VerifyingKey, args: &Args, circuit: &str) -> eyre::Result<()> {
    let path = args.output_dir.join(format!("{circuit}_vk.bin"));
    std::fs::write(&path, bincode::serde::encode_to_vec(vk, bincode::config::standard())?)?;
    info!("saved {circuit} vk to {}", path.display());

    // Also save the human-readable vkey hash for Solidity tests.
    let hash_path = args.output_dir.join(format!("{circuit}_vk_hash.txt"));
    std::fs::write(&hash_path, vk.bytes32())?;
    info!("saved {circuit} vk hash to {}", hash_path.display());
    Ok(())
}

fn extract_recursion_proof(
    proof: &SP1ProofWithPublicValues,
) -> eyre::Result<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>> {
    match &proof.proof {
        SP1Proof::Compressed(p) => Ok((**p).clone()),
        other => eyre::bail!("expected compressed proof, got {other}"),
    }
}

fn save_bundle_artifacts(plonk: &SP1ProofWithPublicValues, args: &Args) -> eyre::Result<()> {
    let pv_path = args.output_dir.join("bundle_public_values.bin");
    std::fs::write(&pv_path, plonk.public_values.to_vec())?;
    info!("saved bundle public values to {}", pv_path.display());

    let proof_bytes_path = args.output_dir.join("bundle_proof_bytes.bin");
    std::fs::write(&proof_bytes_path, plonk.bytes())?;
    info!("saved bundle proof bytes to {}", proof_bytes_path.display());

    if let SP1Proof::Plonk(p) = &plonk.proof {
        info!("bundle Plonk public inputs: {:?}", p.public_inputs);
    }

    Ok(())
}
