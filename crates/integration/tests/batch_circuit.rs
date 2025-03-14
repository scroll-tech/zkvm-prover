use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::{
        batch::{BatchProverTester, BatchTaskBuildingTester},
        chunk::MultiChunkProverTester,
    },
    utils::build_batch_task,
};

#[test]
fn test_execute() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    let (_, app_config, exe_path) = BatchProverTester::load()?;
    let task = BatchProverTester::gen_proving_task()?;

    BatchProverTester::execute(app_config.clone(), &task, exe_path.clone())?;

    Ok(())
}

#[test]
fn test_e2e_execute() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    let (_, app_config, exe_path) = BatchTaskBuildingTester::load()?;

    let task = BatchTaskBuildingTester::gen_proving_task()?;
    BatchTaskBuildingTester::execute(app_config.clone(), &task, exe_path.clone())?;

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    BatchTaskBuildingTester::setup()?;

    prove_verify_single::<BatchTaskBuildingTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;

    let batch_task = build_batch_task(&outcome.tasks, &outcome.proofs, Default::default());
    prove_verify_single::<BatchProverTester>(Some(batch_task))?;

    Ok(())
}
