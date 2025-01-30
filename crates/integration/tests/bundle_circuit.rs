use std::path::Path;

use scroll_zkvm_circuit_input_types::{PublicInputs, bundle::BundleInfo};
use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single_evm,
    testers::{
        PATH_TESTDATA, batch::MultiBatchProverTester, bundle::BundleProverTester,
        chunk::MultiChunkProverTester,
    },
    utils::{LastHeader, build_batch_task},
};
use scroll_zkvm_prover::{
    BatchProof, BundleProof, task::bundle::BundleProvingTask, utils::read_json_deep,
};

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

fn expected_bundle_info(proofs: &[BatchProof]) -> BundleInfo {
    let (first_batch, last_batch) = (
        &proofs
            .first()
            .expect("at least one batch in bundle")
            .metadata
            .batch_info,
        &proofs
            .last()
            .expect("at least one batch in bundle")
            .metadata
            .batch_info,
    );

    let chain_id = first_batch.chain_id;
    let num_batches = u32::try_from(proofs.len()).expect("num_batches: u32");
    let prev_state_root = first_batch.parent_batch_hash;
    let prev_batch_hash = first_batch.parent_batch_hash;
    let post_state_root = last_batch.state_root;
    let batch_hash = last_batch.batch_hash;
    let withdraw_root = last_batch.withdraw_root;

    BundleInfo {
        chain_id,
        num_batches,
        prev_state_root,
        prev_batch_hash,
        post_state_root,
        batch_hash,
        withdraw_root,
    }
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

    // Expected bundle info and public-input hash.
    let bundle_info = expected_bundle_info(&outcome.proofs);
    let bundle_pi = bundle_info.pi_hash();

    // Construct bundle task using batch tasks and batch proofs.
    let bundle_task = BundleProvingTask {
        batch_proofs: outcome.proofs,
    };
    let outcome = prove_verify_single_evm::<BundleProverTester>(Some(bundle_task))?;

    tracing::info!("bundle pi (expected) = {:?}", bundle_pi);
    tracing::info!(
        "bundle pi (observed) = {:?}",
        outcome.proofs[0].proof.instances
    );

    Ok(())
}

#[test]
fn verify_evm_proof() -> eyre::Result<()> {
    let evm_proof = read_json_deep::<_, BundleProof>(Path::new(PATH_TESTDATA).join("proofs").join("bundle-0x60f88f3e46c74362cd93c07724c9ef8e56e391317df6504b905c3c16e81de2e4-0x30d2f51e20e9a4ecd460466af9c81d13daad4fb8d1ca1e42dab30603374f7e5f.json"))?;

    Ok(())
}
