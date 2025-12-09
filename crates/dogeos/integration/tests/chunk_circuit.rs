use dogeos_zkvm_integration::testers::chunk::{ChunkProverTester, exec_chunk, mock_chunk_witness};
use scroll_zkvm_integration::ProverTester;

#[test]
fn test_execute() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;

    let wit = mock_chunk_witness()?;
    exec_chunk(&wit)?;

    Ok(())
}
