use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::{
        batch::{BatchProverTester, MultiBatchProverTester},
        chunk::{ChunkProverTester, MultiChunkProverTester},
    },
    utils::build_batch_task,
};
use scroll_zkvm_prover::{ChunkProof, task::batch::BatchProvingTask, utils::read_json_deep};

fn load_recent_chunk_proofs() -> eyre::Result<BatchProvingTask> {
    let proof_path = glob::glob("../../.output/chunk-tests-*/chunk/proofs/chunk-*.json")?
        .next()
        .unwrap()?;
    println!("proof_path: {:?}", proof_path);
    let chunk_proof = read_json_deep::<_, ChunkProof>(&proof_path)?;

    let chunk_task = ChunkProverTester::gen_proving_task()?;

    let task = build_batch_task(
        &[chunk_task],
        &[chunk_proof],
        scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
        Default::default(),
    );
    Ok(task)
}

#[test]
fn test_execute() -> eyre::Result<()> {
    MultiBatchProverTester::setup()?;

    let (_, app_config, exe_path) = MultiBatchProverTester::load()?;

    // let tasks = MultiBatchProverTester::gen_multi_proving_tasks()?;
    let tasks = vec![load_recent_chunk_proofs()?];
    for task in tasks {
        MultiBatchProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    let task = load_recent_chunk_proofs()?;
    prove_verify_single::<BatchProverTester>(Some(task))?;

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
