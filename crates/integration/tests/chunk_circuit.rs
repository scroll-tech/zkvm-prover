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
