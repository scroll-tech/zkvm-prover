use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::{
        batch::MultiBatchProverTester, bundle::BundleProverTester, chunk::MultiChunkProverTester,
    },
    utils::build_batch_task,
};
use scroll_zkvm_prover::task::bundle::BundleProvingTask;

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    BundleProverTester::setup()?;

    let _outcome = prove_verify_single::<BundleProverTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    BundleProverTester::setup()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;
    let (chunk_tasks, chunk_proofs) = (outcome.tasks, outcome.proofs);
    assert_eq!(chunk_tasks.len(), chunk_proofs.len());
    assert_eq!(chunk_tasks.len(), 3);

    // Construct batch tasks using chunk tasks and chunk proofs.
    let batch_task_1 = build_batch_task(
        &chunk_tasks[0..1],
        &chunk_proofs[0..1],
        scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
        Default::default(),
    );
    let batch_task_2 = build_batch_task(
        &chunk_tasks[1..],
        &chunk_proofs[1..],
        scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
        Default::default(),
    );

    let outcome =
        prove_verify_multi::<MultiBatchProverTester>(Some(&[batch_task_1, batch_task_2]))?;
    let (_batch_tasks, batch_proofs) = (outcome.tasks, outcome.proofs);

    // Construct bundle task using batch tasks and batch proofs.
    let bundle_task = BundleProvingTask { batch_proofs };
    let _outcome = prove_verify_single::<BundleProverTester>(Some(bundle_task))?;

    Ok(())
}
