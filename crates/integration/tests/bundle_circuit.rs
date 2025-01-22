use scroll_zkvm_integration::{
    prove_verify_multi, prove_verify_single, setup,
    testers::{
        batch::MultiBatchProverTester, bundle::BundleProverTester, chunk::MultiChunkProverTester,
    },
};

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    setup()?;

    let _outcome = prove_verify_single::<BundleProverTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    setup()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;
    let (_chunk_tasks, _chunk_proofs) = (outcome.tasks, outcome.proofs);

    // TODO: construct batch tasks using chunk tasks and chunk proofs.
    let batch_tasks = None;
    let outcome = prove_verify_multi::<MultiBatchProverTester>(batch_tasks)?;
    let (_batch_tasks, _batch_proofs) = (outcome.tasks, outcome.proofs);

    // TODO: construct bundle task using batch tasks and batch proofs.
    let bundle_task = None;
    let _outcome = prove_verify_single::<BundleProverTester>(bundle_task)?;

    Ok(())
}
