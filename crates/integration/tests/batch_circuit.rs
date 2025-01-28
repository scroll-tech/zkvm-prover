use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single, setup_logger,
    testers::{
        batch::{BatchProverTester, MultiBatchProverTester},
        chunk::MultiChunkProverTester,
    },
};

#[test]
fn test_execute() -> eyre::Result<()> {
    setup_logger()?;

    MultiBatchProverTester::setup()?;

    let elf = MultiBatchProverTester::build()?;

    let (app_config, exe_path) = MultiBatchProverTester::transpile(elf)?;

    let task = MultiBatchProverTester::gen_proving_task()?;

    MultiBatchProverTester::execute(app_config.clone(), &task, exe_path.clone())?;

    Ok(())
}

#[test]
fn setup_prove_verify_single_chunk() -> eyre::Result<()> {
    setup_logger()?;

    let _outcome = prove_verify_single::<BatchProverTester>(None)?;

    Ok(())
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    setup_logger()?;

    let _outcome = prove_verify_single::<MultiBatchProverTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    setup_logger()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;
    let (_chunk_tasks, _chunk_proofs) = (outcome.tasks, outcome.proofs);

    // TODO: construct batch task from chunk tasks and chunk proofs.
    let batch_task = None;
    let _outcome = prove_verify_single::<BatchProverTester>(batch_task)?;

    Ok(())
}
