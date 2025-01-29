use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::{
        batch::{BatchProverTester, MultiBatchProverTester},
        chunk::MultiChunkProverTester,
    },
    utils::build_batch_task,
};

#[test]
fn setup() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    let elf = BatchProverTester::build()?;

    let (app_config, _) = BatchProverTester::transpile(elf)?;

    BatchProverTester::keygen(app_config)?;

    Ok(())
}

#[test]
fn test_execute() -> eyre::Result<()> {
    MultiBatchProverTester::setup()?;

    let elf = MultiBatchProverTester::build()?;

    let (app_config, exe_path) = MultiBatchProverTester::transpile(elf)?;

    for task in MultiBatchProverTester::gen_multi_proving_tasks()? {
        MultiBatchProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    prove_verify_single::<BatchProverTester>(None)?;

    Ok(())
}

#[test]
fn setup_prove_verify_multi() -> eyre::Result<()> {
    MultiBatchProverTester::setup()?;

    prove_verify_single::<MultiBatchProverTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;

    let batch_task = build_batch_task(
        &outcome.tasks,
        &outcome.proofs,
        scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
        Default::default(),
    );
    prove_verify_single::<BatchProverTester>(Some(batch_task))?;

    Ok(())
}
