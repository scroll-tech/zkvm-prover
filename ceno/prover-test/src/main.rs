mod witness;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use ceno_emul::Program;
use ceno_host::CenoStdin;
use ceno_zkvm::e2e::{MultiProver, Preset, run_e2e_full_trace_verify, setup_platform};
use ceno_zkvm::scheme::constants::MAX_NUM_VARIABLES;
use clap::Parser;
use mpcs::{Basefold, BasefoldRSParams, Jagged, SecurityLevel};
use scroll_zkvm_types_base::public_inputs::scroll::{
    batch::BatchInfo, bundle::BundleInfo, chunk::ChunkInfo,
};
use scroll_zkvm_types_base::public_inputs::{MultiVersionPublicInputs, PublicInputs};
use tiny_keccak::{Hasher, Keccak};
use tracing::info;

type CenoPcs = Jagged<Basefold<ff_ext::BabyBearExt4, BasefoldRSParams>>;
type CenoSdk = ceno_sdk::sdk::CenoSDK<ff_ext::BabyBearExt4, CenoPcs>;

const MAX_CYCLE_PER_SHARD: u64 = 1 << 29;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Circuit to prove (chunk, batch, bundle).
    #[arg(long, default_value = "chunk")]
    circuit: String,

    /// Require the CUDA Ceno prover.
    #[arg(long)]
    gpu: bool,

    /// Directory containing compiled Ceno ELFs.
    #[arg(long, default_value = "releases/dev/ceno")]
    elf_dir: PathBuf,

    /// Directory to write proof artifacts.
    #[arg(long, default_value = "releases/dev/ceno/prover-test")]
    output_dir: PathBuf,

    /// Inclusive block range `start..=end` for chunk proving.
    #[arg(long)]
    block_range: Option<String>,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    if args.gpu {
        require_gpu_feature()?;
    }

    let output_dir = args.output_dir.join(&args.circuit);
    std::fs::create_dir_all(&output_dir)?;

    match args.circuit.as_str() {
        "chunk" => prove_chunk(&args, &output_dir),
        "batch" => prove_batch(&args, &output_dir),
        "bundle" => prove_bundle(&args, &output_dir),
        other => eyre::bail!("unknown circuit: {other}"),
    }
}

#[cfg(feature = "gpu")]
fn require_gpu_feature() -> eyre::Result<()> {
    println!("CUDA Backend Enabled");
    Ok(())
}

#[cfg(not(feature = "gpu"))]
fn require_gpu_feature() -> eyre::Result<()> {
    eyre::bail!(
        "Ceno GPU proving requested, but scroll-zkvm-ceno-prover-test was built without --features gpu"
    )
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

fn prove_chunk(args: &Args, output_dir: &Path) -> eyre::Result<()> {
    let block_range = match &args.block_range {
        Some(r) => parse_block_range(r)?,
        None => witness::preset_chunk_block_range(),
    };
    info!("building chunk witness for blocks {:?}", block_range);
    let chunk_witness = witness::build_chunk_witness(block_range.into_iter())?;
    let version = witness::testing_version();
    let chunk_info = ChunkInfo::try_from(chunk_witness.clone())
        .map_err(|e| eyre::eyre!("chunk execution failed: {e}"))?;
    let pi_hash: B256 = (chunk_info, version).pi_hash();

    let mut stdin = CenoStdin::default();
    stdin.write(&chunk_witness)?;
    prove_circuit(args, output_dir, "chunk", stdin, pi_hash)
}

fn prove_batch(args: &Args, output_dir: &Path) -> eyre::Result<()> {
    let chunk_witnesses: Vec<_> = witness::preset_batch_chunk_ranges()
        .into_iter()
        .map(|r| witness::build_chunk_witness(r.into_iter()))
        .collect::<eyre::Result<Vec<_>>>()?;
    let batch_witness = witness::build_batch_witness(&chunk_witnesses)?;
    let version = witness::testing_version();
    let child_pi_hashes: Vec<[u8; 32]> = batch_witness
        .chunk_infos
        .iter()
        .map(|info| *info.pi_hash_by_version(version).as_ref())
        .collect();
    let batch_info: BatchInfo = witness::batch_info_from_witness(&batch_witness)?;
    let pi_hash: B256 = (batch_info, version).pi_hash();

    let mut stdin = CenoStdin::default();
    stdin.write(&child_pi_hashes)?;
    stdin.write(&batch_witness)?;
    prove_circuit(args, output_dir, "batch", stdin, pi_hash)
}

fn prove_bundle(args: &Args, output_dir: &Path) -> eyre::Result<()> {
    let batch_witnesses = witness::preset_batch_witnesses()?;
    let bundle_witness = witness::build_bundle_witness(&batch_witnesses)?;
    let version = witness::testing_version();
    let child_pi_hashes: Vec<[u8; 32]> = bundle_witness
        .batch_infos
        .iter()
        .map(|info| *info.pi_hash_by_version(version).as_ref())
        .collect();
    let bundle_info = BundleInfo::from(&bundle_witness);
    let pi_hash: B256 = (bundle_info, version).pi_hash();

    let mut stdin = CenoStdin::default();
    stdin.write(&child_pi_hashes)?;
    stdin.write(&bundle_witness)?;
    prove_circuit(args, output_dir, "bundle", stdin, pi_hash)
}

fn prove_circuit(
    args: &Args,
    output_dir: &Path,
    circuit: &str,
    stdin: CenoStdin,
    pi_hash: B256,
) -> eyre::Result<()> {
    let elf = load_elf(args, circuit)?;
    let program = Program::load_elf(&elf, u32::MAX)
        .map_err(|err| eyre::eyre!("failed to load Ceno ELF: {err:?}"))?;
    let stack_size = 128 * 1024 * 1024;
    let heap_size = 128 * 1024 * 1024;
    let platform = setup_platform(Preset::Ceno, &program, stack_size, heap_size);

    let max_cell_per_shard = std::env::var("CENO_MAX_CELL_PER_SHARD")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or((1 << 30) * 6 / 4 / 2);
    println!("ceno max_cell_per_shard: {max_cell_per_shard}");

    let mut sdk = CenoSdk::new_with_app_config(
        program,
        platform,
        MultiProver::new(0, 1, max_cell_per_shard, MAX_CYCLE_PER_SHARD),
    );

    let setup_start = Instant::now();
    sdk.init_base_prover(MAX_NUM_VARIABLES, SecurityLevel::default());
    println!(
        "ceno {circuit} base prover setup time: {:?}",
        setup_start.elapsed()
    );

    let public_io_digest = ceno_commit_digest(pi_hash.as_slice());
    std::fs::write(output_dir.join("pi_hash.bin"), pi_hash.as_slice())?;
    std::fs::write(
        output_dir.join("public_io_digest.bin"),
        digest_words_as_bytes(public_io_digest),
    )?;
    std::fs::write(output_dir.join("hints.bin"), Vec::<u8>::from(&stdin))?;

    let prove_start = Instant::now();
    let proofs = sdk.generate_base_proof(stdin, public_io_digest, usize::MAX, None);
    let app_proving_time = prove_start.elapsed();
    println!("ceno {circuit} app proving time (setup excluded): {app_proving_time:?}");
    std::fs::write(
        output_dir.join("app_proof.bitcode"),
        bitcode::serialize(&proofs)?,
    )?;

    let verifier = sdk.create_zkvm_verifier();
    run_e2e_full_trace_verify(&verifier, proofs.clone(), Some(0), usize::MAX);
    println!("ceno {circuit} app proof verified");

    let app_vk = sdk.get_app_vk();
    std::fs::write(
        output_dir.join("app_vk.bitcode"),
        bitcode::serialize(&app_vk)?,
    )?;

    let agg_prover = sdk
        .init_agg_prover()
        .map_err(|err| eyre::eyre!("{err:?}"))?;
    let root_start = Instant::now();
    let timed_root_output = agg_prover.prove_with_root_vk_timed(&proofs)?;
    let root_output = timed_root_output.root_output;
    let root_wall_time = root_start.elapsed();
    let root_proving_time = timed_root_output.timings.total_create_proof;
    println!(
        "ceno {circuit} root proving time (setup excluded): {:?}",
        root_proving_time
    );
    let total_proving_time = app_proving_time + root_proving_time;
    println!(
        "ceno {circuit} total proving time (setup excluded): {:?}",
        total_proving_time
    );
    std::fs::write(
        output_dir.join("proving_time_ms.txt"),
        duration_millis(total_proving_time).to_string(),
    )?;
    agg_prover
        .verify_root_proof(&root_output.root_vk, &root_output.root_proof)
        .map_err(|err| eyre::eyre!("root proof verification failed: {err:?}"))?;
    println!("ceno {circuit} root proof verified after root proving wall time {root_wall_time:?}");

    let root_bytes =
        bincode::serde::encode_to_vec(&root_output.root_proof, bincode::config::standard())?;
    std::fs::write(output_dir.join("root_proof.bin"), root_bytes)?;
    let root_vk_bytes =
        bincode::serde::encode_to_vec(&root_output.root_vk, bincode::config::standard())?;
    std::fs::write(output_dir.join("root_vk.bin"), root_vk_bytes)?;

    Ok(())
}

fn load_elf(args: &Args, circuit: &str) -> eyre::Result<Vec<u8>> {
    let path = args.elf_dir.join(circuit).join("app");
    if !path.exists() {
        eyre::bail!(
            "Ceno ELF not found at {}; run `make build-guest-ceno` first",
            path.display()
        );
    }
    Ok(std::fs::read(path)?)
}

fn ceno_commit_digest(bytes: &[u8]) -> [u32; 8] {
    let mut keccak = Keccak::v256();
    keccak.update(bytes);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);
    core::array::from_fn(|i| {
        u32::from_le_bytes([
            digest[i * 4],
            digest[i * 4 + 1],
            digest[i * 4 + 2],
            digest[i * 4 + 3],
        ])
    })
}

fn digest_words_as_bytes(words: [u32; 8]) -> Vec<u8> {
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}

fn duration_millis(duration: Duration) -> u128 {
    duration.as_millis()
}
