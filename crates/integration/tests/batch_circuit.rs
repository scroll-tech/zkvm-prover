use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single, setup_logger,
    testers::{
        batch::{BatchProverTester, MultiBatchProverTester},
        chunk::MultiChunkProverTester,
    },
    utils::build_batch_task,
};

#[test]
fn test_execute() -> eyre::Result<()> {
    setup_logger()?;

    MultiBatchProverTester::setup()?;

    let elf = MultiBatchProverTester::build()?;

    let (app_config, exe_path) = MultiBatchProverTester::transpile(elf)?;

    let task = MultiBatchProverTester::gen_proving_task()?;

    MultiBatchProverTester::execute(app_config.clone(), &task, exe_path.clone())?;

    Ok(())
}

#[test]
fn setup_prove_verify_single_chunk() -> eyre::Result<()> {
    setup_logger()?;

    let _outcome = prove_verify_single::<BatchProverTester>(None)?;

    Ok(())
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    setup_logger()?;

    let _outcome = prove_verify_single::<MultiBatchProverTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    use std::str::FromStr;
    
    setup_logger()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;
    let (chunk_tasks, mut chunk_proofs) = (outcome.tasks, outcome.proofs);

    // TODO: now we have to add an hardcoded withdraw root here
    for proof in &mut chunk_proofs {
        proof.metadata.chunk_info.withdraw_root = sbv::primitives::B256::from_str(
            "0x7ed4c7d56e2ed40f65d25eecbb0110f3b3f4db68e87700287c7e0cedcb68272c",
        )
        .unwrap();        
    }

    let batch_task = build_batch_task(
        &chunk_tasks,
        &chunk_proofs,
        scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
        Default::default(),
    );
    let _outcome = prove_verify_single::<BatchProverTester>(Some(batch_task))?;

    Ok(())
}
