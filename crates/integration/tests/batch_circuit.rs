use scroll_zkvm_integration::{
    prove_verify_multi, prove_verify_single, setup,
    testers::{batch::BatchProverTester, chunk::MultiChunkProverTester},
};

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    setup()?;

    let _outcome = prove_verify_single::<BatchProverTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    setup()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;
    let (_chunk_tasks, _chunk_proofs) = (outcome.tasks, outcome.proofs);

    // TODO: construct batch task from chunk tasks and chunk proofs.
    let batch_task = None;
    let _outcome = prove_verify_single::<BatchProverTester>(batch_task)?;

    Ok(())
}
