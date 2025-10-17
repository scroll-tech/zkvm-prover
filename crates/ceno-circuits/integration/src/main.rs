use std::fs::File;
use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform};
use ceno_zkvm::scheme::{create_backend, create_prover};
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::BasefoldDefault;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;
use cargo_metadata::MetadataCommand;
use sbv_core::BlockWitness;
use scroll_zkvm_types_chunk::ChunkWitness;

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
        .map(|rdr| serde_json::from_reader::<_, sbv_primitives::legacy_types::BlockWitness>(rdr).unwrap())
        .map(BlockWitness::from)
        .collect::<Vec<_>>();
    ChunkWitness::new(&blocks, B256::ZERO, ForkName::Feynman)
}

#[cfg(not(feature = "scroll"))]
fn load_witness() -> ChunkWitness {
    let base = WORKSPACE_ROOT.join("crates/integration/testdata/ethereum");
    let blocks = (23588347..=23588347)
        .map(|n| base.join(format!("{n}.json")))
        .map(|path| File::open(&path).unwrap())
        .map(|rdr| serde_json::from_reader::<_, BlockWitness>(rdr).unwrap())
        .collect::<Vec<_>>();
    ChunkWitness::new(&blocks)
}

fn main() -> eyre::Result<()> {
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
    let start = Instant::now();
    let result = run_e2e_with_checkpoint::<E, Pcs, _, _>(
        create_prover(backend.clone()),
        program.clone(),
        platform.clone(),
        &Vec::from(&hints),
        &[],
        max_steps,
        Checkpoint::Complete,
    );
    let duration = start.elapsed();
    println!("run_e2e_with_checkpoint took: {:?}", duration);
    let _proof = result.proof.expect("PrepSanityCheck do not provide proof");
    let _vk = result.vk.expect("PrepSanityCheck do not provide verifier");

    Ok(())
}
