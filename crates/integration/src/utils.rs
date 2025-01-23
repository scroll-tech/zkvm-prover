use scroll_zkvm_prover::{
    ChunkProof,
    task::{batch::BatchProvingTask, chunk::ChunkProvingTask},
};

pub fn build_batch_task(
    chunk_tasks: &[ChunkProvingTask],
    chunk_proofs: &[ChunkProof],
) -> BatchProvingTask {
    // Sanity check.
    assert_eq!(chunk_tasks.len(), chunk_proofs.len());

    unimplemented!()
}
