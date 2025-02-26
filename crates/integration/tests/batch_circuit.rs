use scroll_zkvm_integration::{
    ProverTester, get_chunk_prover, prove_verify_multi, prove_verify_single,
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
    BatchProverTester::setup()?;

    let (_path_app_config, app_config, path_exe) = BatchProverTester::load()?;

    let task = BatchProverTester::gen_proving_task()?;
    BatchProverTester::execute(app_config.clone(), &task, path_exe)?;

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    BatchProverTester::setup()?;

    // let task = load_recent_chunk_proofs()?;
    prove_verify_single::<BatchProverTester>(None)?;

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

    let outcome = prove_verify_single::<ChunkProverTester>(None)?;

    let batch_task = build_batch_task(
        &outcome.tasks,
        &outcome.proofs,
        scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
        Default::default(),
    );

    let batch_task_ser = serde_json::to_string(&batch_task)?;
    let batch_task_de = serde_json::from_str::<BatchProvingTask>(&batch_task_ser)?;

    prove_verify_single::<BatchProverTester>(Some(batch_task_de))?;

    Ok(())
}

#[test]
fn verify_proofs() -> eyre::Result<()> {
    let task = BatchProverTester::gen_proving_task()?;
    let chunk_prover = get_chunk_prover()?;

    for chunk_proof in task.chunk_proofs.iter() {
        chunk_prover.verify_proof(chunk_proof)?;
    }

    Ok(())
}
