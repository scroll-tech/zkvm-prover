use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester},
};
use scroll_zkvm_prover::{ChunkProver, task::ProvingTask};

#[test]
fn test_execute() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    let (path_app_config, _app_config, path_exe) = ChunkProverTester::load()?;
    let task = ChunkProverTester::gen_proving_task()?;
    let prover = ChunkProver::setup(&path_exe, &path_app_config, None)?;
    prover.execute_guest(&task.build_guest_input()?)?;

    Ok(())
}

#[test]
fn test_execute_multi() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    let elf = MultiChunkProverTester::build()?;

    let (_, app_config, exe_path) = MultiChunkProverTester::transpile(elf, None)?;

    for task in MultiChunkProverTester::gen_multi_proving_tasks()? {
        MultiChunkProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

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
