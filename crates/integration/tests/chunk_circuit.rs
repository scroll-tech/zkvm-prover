use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single, setup_logger,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester},
};

#[test]
fn setup() -> eyre::Result<()> {
    setup_logger()?;

    ChunkProverTester::setup()?;

    let elf = ChunkProverTester::build()?;

    let (app_config, _) = ChunkProverTester::transpile(elf)?;

    ChunkProverTester::keygen(app_config)?;

    Ok(())
}

#[test]
fn test_execute() -> eyre::Result<()> {
    setup_logger()?;

    ChunkProverTester::setup()?;

    let elf = ChunkProverTester::build()?;

    let (app_config, exe_path) = ChunkProverTester::transpile(elf)?;

    for task in ChunkProverTester::gen_multi_proving_tasks()? {
        ChunkProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

    Ok(())
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    setup_logger()?;

    let _outcome = prove_verify_single::<ChunkProverTester>(None)?;

    Ok(())
}

#[test]
fn multi_chunk() -> eyre::Result<()> {
    setup_logger()?;

    let _outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;

    Ok(())
}
