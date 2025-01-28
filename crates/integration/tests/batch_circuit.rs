use scroll_zkvm_integration::{
    prove_verify_multi, prove_verify_single, setup_logger,
    testers::{batch::BatchProverTester, chunk::MultiChunkProverTester},
    utils::build_batch_task,
};
use scroll_zkvm_prover::{
    ChunkProof,
    task::{batch::BatchProvingTask, chunk::ChunkProvingTask},
    utils::read_json,
};

#[test]
fn batch_simple_execution() -> eyre::Result<()> {
    use BatchProverTester as T;
    use scroll_zkvm_integration::ProverTester;
    setup_logger()?;

    // Setup test-run directories.
    T::setup()?;

    // Build the ELF binary from the circuit program.
    let elf = T::build()?;

    // Transpile the ELF into a VmExe.
    let (app_config, exe_path) = T::transpile(elf)?;
    // read task
    let task: BatchProvingTask = {
        let block_dir = "testdata/";

        let blk_names = [
            "12508460.json",
            "12508461.json",
            "12508462.json",
            "12508463.json",
        ];

        let blk_witness =
            |n| read_json::<_, sbv::primitives::types::BlockWitness>(format!("{block_dir}/{}", n));

        // manual match to chunk tasks
        let chk_task = [
            ChunkProvingTask {
                block_witnesses: vec![blk_witness(blk_names[0])?],
            },
            ChunkProvingTask {
                block_witnesses: vec![blk_witness(blk_names[1])?],
            },
            ChunkProvingTask {
                block_witnesses: vec![blk_witness(blk_names[2])?, blk_witness(blk_names[3])?],
            },
        ];

        let proof_dir = "testdata/chunk";
        let pathes = [
            "chunk-proof--12508460-12508460.json",
            "chunk-proof--12508461-12508461.json",
            "chunk-proof--12508462-12508463.json",
        ];
        let chunk_proofs = pathes.map(|p| {
            let p = format!("{proof_dir}/{p}");
            ChunkProof::from_json(p).unwrap()
        });
        build_batch_task(
            &chk_task,
            &chunk_proofs,
            scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
            Default::default(),
        )
        // read_json("testdata/batch-task-with-blob.json")?;
    };

    T::execute(app_config, &task, exe_path)?;

    Ok(())
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    setup_logger()?;

    let _outcome = prove_verify_single::<BatchProverTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    setup_logger()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;
    let (_chunk_tasks, _chunk_proofs) = (outcome.tasks, outcome.proofs);

    // TODO: construct batch task from chunk tasks and chunk proofs.
    let batch_task = None;
    let _outcome = prove_verify_single::<BatchProverTester>(batch_task)?;

    Ok(())
}
