use sbv::primitives::types::BlockWitness;
//use sbv::primitives::BlockWitness;
use scroll_zkvm_integration::{
    prove_verify_multi, prove_verify_single, testers::{
        batch::{BatchProverTester, MultiBatchProverTester},
        chunk::{ChunkProverTester, MultiChunkProverTester},
    }, utils::build_batch_task, ProverTester
};
use scroll_zkvm_prover::{utils::read_json_deep, ChunkProof};
use scroll_zkvm_prover::utils::read_json;
use scroll_zkvm_prover::task::chunk::ChunkProvingTask;  
#[test]
fn test_execute() -> eyre::Result<()> {
    MultiBatchProverTester::setup()?;

    let elf = MultiBatchProverTester::build()?;

    let (_, app_config, exe_path) = MultiBatchProverTester::transpile(elf)?;

    //let tasks = MultiBatchProverTester::gen_multi_proving_tasks()?;
    let tasks = {
        println!("cwd: {:?}", std::env::current_dir());
        // glob last result of "".output/chunk-tests-*/chunk/proofs/chunk-*.json"
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
        vec![task]
    };
    for task in tasks {
        MultiBatchProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    BatchProverTester::setup()?;

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
