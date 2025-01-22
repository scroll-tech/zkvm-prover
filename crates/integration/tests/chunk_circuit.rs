use scroll_zkvm_integration::{
    prove_verify_multi, prove_verify_single, setup_logger,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester},
};

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
