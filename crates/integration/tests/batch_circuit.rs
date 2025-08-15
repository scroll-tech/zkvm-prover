use scroll_zkvm_integration::{
    testers::{
        batch::{BatchProverTester, BatchTaskGenerator},
        chunk::{create_canonical_tasks, preset_chunk_multiple, ChunkProverTester},
        load_local_task,
    }, testing_hardfork, ProverTester
};
use scroll_zkvm_prover::task::ProvingTask;

#[ignore = "need local stuff"]
#[test]
fn test_execute() -> eyre::Result<()> {
    BatchProverTester::setup()?;
    let u_task = load_local_task("batch-task.json")?;
    let stdin = u_task.build_guest_input()?;

    let mut prover = BatchProverTester::load_prover(false)?;

    let _ = prover.execute_and_check(&stdin)?;
    Ok(())
}

#[ignore = "need local stuff"]
#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    BatchProverTester::setup()?;
    let u_task = load_local_task("batch-task.json")?;

    let mut prover = BatchProverTester::load_prover(false)?;

    let _ = prover.gen_proof_universal(&u_task, false)?;

    Ok(())
}

#[test]
fn test_e2e_execute() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    let mut prover = BatchProverTester::load_prover(false)?;
    let mut chunk_prover = ChunkProverTester::load_prover(false)?;

    let mut task = BatchTaskGenerator::from_chunk_tasks(&preset_chunk_multiple(), None);

    let wit = task.get_or_build_witness()?;
    let agg_proofs = task.get_or_build_child_proofs(&mut chunk_prover)?;

    let stdin = BatchProverTester::build_guest_input(
        &wit,
        agg_proofs.iter().map(|p| p.as_stark_proof().unwrap()),
    )?;
    let _ = prover.execute_and_check_with_full_result(&stdin)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    let mut prover = BatchProverTester::load_prover(false)?;
    let mut chunk_prover = ChunkProverTester::load_prover(false)?;
    let mut batch = BatchTaskGenerator::from_chunk_tasks(&preset_chunk_multiple(), None);
    let _ = 
        batch.get_or_build_proof(&mut prover, &mut chunk_prover)?;

    Ok(())
}

#[test]
fn verify_batch_hash_invariant() -> eyre::Result<()> {
    use scroll_zkvm_types::public_inputs::ForkName;
    BatchProverTester::setup()?;

    let outcome_1 = preset_chunk_multiple();
    let outcome_2 = create_canonical_tasks(
        match testing_hardfork() {
            ForkName::EuclidV1 => vec![
                12508460u64..=12508461u64,
                12508462u64..=12508462u64,
                12508463u64..=12508463u64,
            ],
            ForkName::EuclidV2 => vec![1u64..=2u64, 3u64..=3u64, 4u64..=4u64],
            ForkName::Feynman => vec![
                16525000u64..=16525001u64,
                16525002u64..=16525002u64,
                16525003u64..=16525003u64,
            ],
        }
        .into_iter(),
    )?;

    let mut task_1 = BatchTaskGenerator::from_chunk_tasks(&outcome_1, None);
    let mut task_2 = BatchTaskGenerator::from_chunk_tasks(&outcome_2, None);

    // verify the two task has the same blob bytes
    assert_eq!(
        task_1.get_or_build_witness()?.blob_bytes,
        task_2.get_or_build_witness()?.blob_bytes,
    );

    Ok(())
}
