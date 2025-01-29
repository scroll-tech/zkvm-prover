use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single_evm,
    testers::{
        batch::MultiBatchProverTester, bundle::BundleProverTester, chunk::MultiChunkProverTester,
    },
    utils::build_batch_task,
};
use scroll_zkvm_prover::task::bundle::BundleProvingTask;

#[test]
fn setup() -> eyre::Result<()> {
    BundleProverTester::setup()?;

    let elf = BundleProverTester::build()?;

    let (app_config, _) = BundleProverTester::transpile(elf)?;

    BundleProverTester::keygen(app_config)?;

    Ok(())
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    BundleProverTester::setup()?;

    prove_verify_single_evm::<BundleProverTester>(None)?;

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

    // Construct bundle task using batch tasks and batch proofs.
    let bundle_task = BundleProvingTask {
        batch_proofs: outcome.proofs,
    };
    prove_verify_single_evm::<BundleProverTester>(Some(bundle_task))?;

    Ok(())
}
