use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester},
};

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
