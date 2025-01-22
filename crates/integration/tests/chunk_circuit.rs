use scroll_zkvm_integration::{prove_verify_single, setup, testers::chunk::ChunkProverTester};

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    setup()?;

    let _outcome = prove_verify_single::<ChunkProverTester>(None)?;

    Ok(())
}
