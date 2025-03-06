use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester},
};
use scroll_zkvm_prover::task::ProvingTask;

#[test]
fn test_execute() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    let (_, app_config, exe_path) = MultiChunkProverTester::load()?;

    for task in MultiChunkProverTester::gen_multi_proving_tasks()? {
        MultiChunkProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

    Ok(())
}

#[test]
fn test_profiling() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    let (path_app_config, _, path_exe) = ChunkProverTester::load()?;

    let chunk_prover = scroll_zkvm_prover::Prover::<scroll_zkvm_prover::ChunkProverType>::setup(
        &path_exe,
        &path_app_config,
        None,
        Default::default(),
    )?;

    std::env::set_var("GUEST_PROFILING", "true");

    let task = ChunkProverTester::gen_proving_task()?;
    let stdin = task.build_guest_input()?;
    let (total_cycles, _) = chunk_prover
        .execute_guest(&stdin)?
        .ok_or(eyre::eyre!("execute_guest returned None"))?;

    println!("total cycles = {:?}", total_cycles);

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    prove_verify_single::<ChunkProverTester>(None)?;

    Ok(())
}

#[test]
fn setup_prove_verify_multi() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    prove_verify_multi::<MultiChunkProverTester>(None)?;

    Ok(())
}
