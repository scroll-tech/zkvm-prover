use dogeos_zkvm_integration::testers::chunk::{ChunkProverTester, exec_chunk, mock_chunk_witness};
use scroll_zkvm_integration::{prove_verify, ProverTester};

#[test]
fn test_execute() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;

    let wit = mock_chunk_witness()?;
    exec_chunk(&wit)?;

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;
    let mut prover = ChunkProverTester::load_prover(false)?;

    let wit = mock_chunk_witness()?;
    let _ = prove_verify::<ChunkProverTester>(&mut prover, &wit, &[])?;

    Ok(())
}
