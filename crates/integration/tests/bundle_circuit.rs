use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single_evm,
    testers::{
        batch::MultiBatchProverTester, bundle::BundleProverTester, chunk::MultiChunkProverTester,
    },
    utils::{LastHeader, build_batch_task},
};
use scroll_zkvm_prover::{BatchProof, task::bundle::BundleProvingTask, utils::read_json_deep};

fn load_recent_batch_proofs() -> eyre::Result<BundleProvingTask> {
    let proof_path = glob::glob("../../.output/batch-tests-*/batch/proofs/batch-*.json")?
        .next()
        .unwrap()?;
    println!("proof_path: {:?}", proof_path);
    let batch_proof = read_json_deep::<_, BatchProof>(&proof_path)?;

    let task = BundleProvingTask {
        batch_proofs: vec![batch_proof],
    };
    Ok(task)
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    BundleProverTester::setup()?;

    let task = load_recent_batch_proofs()?;
    prove_verify_single_evm::<BundleProverTester>(Some(task))?;

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
        LastHeader::from(&batch_task_1.batch_header),
    );

    let outcome =
        prove_verify_multi::<MultiBatchProverTester>(Some(&[batch_task_1, batch_task_2]))?;

    // Construct bundle task using batch tasks and batch proofs.
    let bundle_task = BundleProvingTask {
        batch_proofs: outcome.proofs,
    };
    let outcome = prove_verify_single_evm::<BundleProverTester>(Some(bundle_task))?;

    assert_eq!(outcome.proofs.len(), 1, "single bundle proof");

    let expected_pi_hash = &outcome.proofs[0].metadata.bundle_pi_hash;
    let observed_instances = &outcome.proofs[0].proof.instances[0];

    for (i, (&expected, &observed)) in expected_pi_hash
        .iter()
        .zip(observed_instances.iter().skip(14).take(32))
        .enumerate()
    {
        assert_eq!(
            halo2curves_axiom::bn256::Fr::from(u64::from(expected)),
            observed,
            "pi inconsistent at index {i}: expected={expected}, observed={observed:?}"
        );
    }

    Ok(())
}
