use cargo_metadata::MetadataCommand;
use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::e2e::{MultiProver, Preset, run_e2e_proof, run_e2e_verify, setup_platform, setup_program, DEFAULT_MAX_CELLS_PER_SHARDS};
use ceno_zkvm::scheme::hal::ProverDevice;
use ceno_zkvm::scheme::verifier::ZKVMVerifier;
use ceno_zkvm::scheme::{create_backend, create_prover};
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::BasefoldDefault;
use sbv_core::BlockWitness;
use scroll_zkvm_types_chunk::ChunkWitness;
use std::env;
use std::fs::File;
use std::path::Path;
use std::sync::LazyLock;
use ceno_zkvm::scheme::prover::ZKVMProver;
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

type Pcs = BasefoldDefault<E>;
type E = BabyBearExt4;

static WORKSPACE_ROOT: LazyLock<&Path> = LazyLock::new(|| {
    let path = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("failed to execute cargo-metadata")
        .workspace_root
        .into_std_path_buf();
    eprintln!("PROJECT_ROOT_DIR = {}", path.display());
    Box::leak(path.into_boxed_path())
});

fn setup() -> (Vec<u8>, Program, Platform) {
    let stack_size = 128 * 1024 * 1024;
    let heap_size = 128 * 1024 * 1024;
    let pub_io_size = 32;
    println!(
        "stack_size: {stack_size:#x}, heap_size: {heap_size:#x}, pub_io_size: {pub_io_size:#x}"
    );

    let elf_path = WORKSPACE_ROOT
        .join("target")
        .join("riscv32im-ceno-zkvm-elf")
        .join("release")
        .join("scroll-zkvm-ceno-chunk-circuit");
    let elf = std::fs::read(elf_path).unwrap();
    let program = Program::load_elf(&elf, u32::MAX).unwrap();
    let platform = setup_platform(Preset::Ceno, &program, stack_size, heap_size, pub_io_size);
    (elf, program, platform)
}

#[cfg(feature = "scroll")]
fn load_witness() -> ChunkWitness {
    use sbv_primitives::B256;
    use scroll_zkvm_types::public_inputs::ForkName;

    let base = WORKSPACE_ROOT.join("crates/integration/testdata/feynman/witnesses");
    let blocks = (16525000..=16525003)
        .map(|n| base.join(format!("{n}.json")))
        .map(|path| File::open(&path).unwrap())
        .map(|rdr| {
            serde_json::from_reader::<_, sbv_primitives::legacy_types::BlockWitness>(rdr).unwrap()
        })
        .map(BlockWitness::from)
        .collect::<Vec<_>>();
    ChunkWitness::new(&blocks, B256::ZERO, ForkName::Feynman)
}

#[cfg(not(feature = "scroll"))]
fn load_witness() -> ChunkWitness {
    let base = WORKSPACE_ROOT.join("crates/integration/testdata/ethereum");
    let blocks = (23588347..23588348)
        .map(|n| base.join(format!("{n}.json")))
        .map(|path| File::open(&path).unwrap())
        .map(|rdr| serde_json::from_reader::<_, BlockWitness>(rdr).unwrap())
        .collect::<Vec<_>>();
    ChunkWitness::new(&blocks)
}

pub const MAX_CYCLE_PER_SHARD: u64 = 1 << 29;

fn main() -> eyre::Result<()> {
    let profiling_level: usize = env::var("PROFILING")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_default();

    if profiling_level > 0 {
        let fmt_layer = fmt::layer()
            .compact()
            .with_thread_ids(false)
            .with_thread_names(false)
            .without_time();
        let filter_by_profiling_level = filter_fn(move |metadata| {
            (1..=profiling_level)
                .map(|i| format!("profiling_{i}"))
                .any(|field| metadata.fields().field(&field).is_some())
        });
        Registry::default()
            .with(fmt_layer)
            .with(ForestLayer::default())
            .with(filter_by_profiling_level)
            .init()
    } else {
        let fmt_layer = fmt::layer()
            .compact()
            .with_thread_ids(false)
            .with_thread_names(false)
            .without_time();
        Registry::default()
            .with(fmt_layer)
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::DEBUG.into())
                    .from_env_lossy(),
            )
            .init()
    };

    let (elf, program, platform) = setup();

    let (_, security_level) = default_backend_config();
    let max_num_variables = 26;
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);

    let mut hints = CenoStdin::default();
    let wit = load_witness();
    println!("chunk_info = {:#?}", wit.stats());

    let input = bincode::serde::encode_to_vec(&wit, bincode::config::standard())?;
    hints.write(&input)?;

    ceno_host::run(platform.clone(), &elf, &hints, None);

    let max_steps = usize::MAX;
    let proving_device = create_prover(backend.clone());

    let start = std::time::Instant::now();
    let ctx = setup_program::<E>(
        program,
        platform,
        MultiProver::new(0, 1, (1 << 30) * 8 / 4 / 2, MAX_CYCLE_PER_SHARD),
    );
    println!("setup_program done in {:?}", start.elapsed());

    // Keygen
    let start = std::time::Instant::now();
    let (pk, vk) = ctx.keygen_with_pb(proving_device.get_pb());
    println!("keygen done in {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let init_full_mem = ctx.setup_init_mem(&Vec::from(&hints), &[]);
    tracing::debug!("setup_init_mem done in {:?}", start.elapsed());

    let prover = ZKVMProver::new(pk, proving_device);
    let proofs =
        run_e2e_proof::<E, Pcs, _, _>(&ctx, &prover, &init_full_mem, max_steps, false);
    let duration = start.elapsed();
    println!("run_e2e_proof took: {:?}", duration);

    let verifier = ZKVMVerifier::new(vk.clone());
    let start = std::time::Instant::now();
    run_e2e_verify(&verifier, proofs, Some(0), max_steps);
    tracing::debug!("verified in {:?}", start.elapsed());
    Ok(())
}
