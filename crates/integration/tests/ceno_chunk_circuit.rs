use std::io::Write;
use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::e2e::{run_e2e_with_checkpoint, setup_platform, setup_platform_debug, Checkpoint, Preset};
use ceno_zkvm::scheme::{create_backend, create_prover};
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::BasefoldDefault;
use rkyv::util::AlignedVec;
use scroll_zkvm_integration::{setup_logger, PartialProvingTask, ProverTester, WORKSPACE_ROOT};
use scroll_zkvm_integration::testers::chunk::{get_witness_from_env_or_builder, preset_chunk, ChunkProverTester, ChunkTaskGenerator};

type Pcs = BasefoldDefault<E>;
type E = BabyBearExt4;


fn setup() -> (Program, Platform) {
    let stack_size = 128 * 1024 * 1024;
    let heap_size = 128 * 1024 * 1024;
    let pub_io_size = 128 * 1024 * 1024;
    println!("stack_size: {stack_size:#x}, heap_size: {heap_size:#x}, pub_io_size: {pub_io_size:#x}");

    let elf_path = WORKSPACE_ROOT
        .join("target")
        .join("riscv32im-ceno-zkvm-elf")
        .join("release")
        .join("scroll-zkvm-ceno-chunk-circuit");
    let elf = std::fs::read(elf_path).unwrap();
    let program = Program::load_elf(&elf, u32::MAX).unwrap();
    let platform = setup_platform(Preset::Ceno, &program, stack_size, heap_size, pub_io_size);
    (program, platform)
}

#[test]
fn test_ceno_execute() -> eyre::Result<()> {
    setup_logger()?;

    let (program, platform) = setup();

    let (_, security_level) = default_backend_config();
    let max_num_variables = 26;
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);

    let mut hints = CenoStdin::default();
    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    let wit = wit.build_guest_input()?;
    hints.write(&wit)?;

    let max_steps = usize::MAX;
    let result = run_e2e_with_checkpoint::<E, Pcs, _, _>(
        create_prover(backend.clone()),
        program.clone(),
        platform.clone(),
        &Vec::from(&hints),
        &[],
        max_steps,
        Checkpoint::Complete,
    );
    let _proof = result.proof.expect("PrepSanityCheck do not provide proof");
    let _vk = result.vk.expect("PrepSanityCheck do not provide verifier");

    Ok(())
}
