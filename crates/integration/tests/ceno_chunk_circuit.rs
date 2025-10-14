use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform};
use ceno_zkvm::scheme::{create_backend, create_prover};
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::BasefoldDefault;
use scroll_zkvm_integration::testers::chunk::{get_witness_from_env_or_builder, preset_chunk};
use scroll_zkvm_integration::{PartialProvingTask, WORKSPACE_ROOT, setup_logger};
use std::io::Write;
use std::time::Instant;
use scroll_zkvm_types::chunk::execute;

type Pcs = BasefoldDefault<E>;
type E = BabyBearExt4;

fn setup() -> (Vec<u8>, Program, Platform) {
    let stack_size = 128 * 1024 * 1024;
    let heap_size = 128 * 1024 * 1024;
    let pub_io_size = 128 * 1024 * 1024;
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

use once_cell::sync::OnceCell;
use tracing_forest::ForestLayer;
use tracing_subscriber::{Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt, filter::filter_fn};

static PROFILING_INIT: OnceCell<()> = OnceCell::new();

fn setup_ceno_profiling_logger(level: u32) {
    let _ = PROFILING_INIT.get_or_init(|| {
        let profiling_level = level;
        let filter_by_profiling_level = filter_fn(move |metadata| {
            (1..=profiling_level)
                .map(|i| format!("profiling_{i}"))
                .any(|field| metadata.fields().field(&field).is_some())
        });
        let fmt_layer = fmt::layer().compact().with_thread_ids(false).with_thread_names(false).without_time();

        Registry::default()
            .with(ForestLayer::default())
            .with(fmt_layer)
            .with(filter_by_profiling_level)
            .try_init()
            .ok();
    });
}

#[test]
fn test_ceno_execute() -> eyre::Result<()> {
    setup_ceno_profiling_logger(2);

    let (elf, program, platform) = setup();

    let (_, security_level) = default_backend_config();
    let max_num_variables = 26;
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);


    let mut hints = CenoStdin::default();
    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    println!("chunk_info = {:#?}", wit.stats());

    let wit = wit.build_guest_input()?;
    hints.write(&wit)?;

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
