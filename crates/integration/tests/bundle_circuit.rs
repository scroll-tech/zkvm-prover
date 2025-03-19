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
        bundle_info: None,
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
    let batch_task_1 =
        build_batch_task(&chunk_tasks[0..1], &chunk_proofs[0..1], Default::default());
    let batch_task_2 = build_batch_task(
        &chunk_tasks[1..],
        &chunk_proofs[1..],
        LastHeader::from(&batch_task_1.batch_header),
    );

    let outcome =
        prove_verify_multi::<MultiBatchProverTester>(Some(&[batch_task_1, batch_task_2]))?;

    // Construct bundle task using batch tasks and batch proofs.
    let bundle_task = BundleProvingTask {
        batch_proofs: outcome.proofs,
        bundle_info: None,
    };
    let (outcome, verifier, path_assets) =
        prove_verify_single_evm::<BundleProverTester>(Some(bundle_task.clone()))?;

    assert_eq!(outcome.proofs.len(), 1, "single bundle proof");

    // The structure of the halo2-proof's instances is:
    // - 12 instances for accumulator
    // - 2 instances for digests (MUST be checked on-chain)
    // - 32 instances for pi_hash (bundle_pi_hash)
    //
    // We write the 2 digests to disc.
    let evm_proof = outcome.proofs[0].as_proof();
    let digest_1 = evm_proof.instances[0][12];
    let digest_2 = evm_proof.instances[0][13];
    scroll_zkvm_prover::utils::write(
        path_assets.join("digest_1"),
        &digest_1.to_bytes().into_iter().rev().collect::<Vec<u8>>(),
    )?;
    scroll_zkvm_prover::utils::write(
        path_assets.join("digest_2"),
        &digest_2.to_bytes().into_iter().rev().collect::<Vec<u8>>(),
    )?;

    // Verifier all above proofs with the verifier-only mode.
    let verifier = verifier.to_chunk_verifier();
    for proof in chunk_proofs.iter() {
        assert!(verifier.verify_proof(proof.as_proof()));
    }
    let verifier = verifier.to_batch_verifier();
    for proof in bundle_task.batch_proofs.iter() {
        assert!(verifier.verify_proof(proof.as_proof()));
    }
    let verifier = verifier.to_bundle_verifier();
    assert!(verifier.verify_proof_evm(&outcome.proofs[0].as_proof()));

    let expected_pi_hash = &outcome.proofs[0].metadata.bundle_pi_hash;
    let observed_instances = &outcome.proofs[0].as_proof().instances[0];

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
