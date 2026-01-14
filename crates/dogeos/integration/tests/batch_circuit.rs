use dogeos_zkvm_integration::testers::batch::{BatchProverTester, mock_batch_witness};
use dogeos_zkvm_integration::testers::chunk::{ChunkProverTester, mock_chunk_witness};
use scroll_zkvm_integration::{ProverTester, prove_verify};

#[test]
fn test_e2e_execute() -> eyre::Result<()> {
    BatchProverTester::setup(true)?;

    let prover = BatchProverTester::load_prover(false)?;
    let mut chunk_prover = ChunkProverTester::load_prover(false)?;

    let chunk_witness = mock_chunk_witness()?;
    let chunk_proof = prove_verify::<ChunkProverTester>(&mut chunk_prover, &chunk_witness, &[])?;

    let batch_witness = mock_batch_witness(&chunk_witness)?;

    let stdin = BatchProverTester::build_guest_input(
        &batch_witness,
        [chunk_proof.as_stark_proof().unwrap()].into_iter(),
    )?;
    let _ = prover.execute_and_check_with_full_result(&stdin)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    BatchProverTester::setup(true)?;

    let mut prover = BatchProverTester::load_prover(false)?;
    let mut chunk_prover = ChunkProverTester::load_prover(false)?;

    let chunk_witness = mock_chunk_witness()?;
    let chunk_proof = prove_verify::<ChunkProverTester>(&mut chunk_prover, &chunk_witness, &[])?;

    let batch_witness = mock_batch_witness(&chunk_witness)?;
    prove_verify::<BatchProverTester>(
        &mut prover,
        &batch_witness,
        &[chunk_proof],
    )?;

    Ok(())
}
