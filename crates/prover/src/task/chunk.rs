use openvm_sdk::StdIn;
use sbv::primitives::types::BlockWitness;

use crate::task::ProvingTask;

/// Message indicating a sanity check failure.
const CHUNK_SANITY_MSG: &str = "chunk must have at least one block";

/// Proving task for the [`ChunkCircuit`][scroll_zkvm_chunk_circuit].
///
/// The identifier for a chunk proving task is:
/// - {first_block_number}-{last_block_number}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChunkProvingTask {
    /// Witnesses for every block in the chunk.
    pub block_witnesses: Vec<BlockWitness>,
}

impl ProvingTask for ChunkProvingTask {
    fn identifier(&self) -> String {
        assert!(!self.block_witnesses.is_empty(), "{CHUNK_SANITY_MSG}",);

        let (first, last) = (
            self.block_witnesses
                .first()
                .expect(CHUNK_SANITY_MSG)
                .header
                .number,
            self.block_witnesses
                .last()
                .expect(CHUNK_SANITY_MSG)
                .header
                .number,
        );

        format!("{first}-{last}")
    }

    fn build_guest_input(&self) -> Result<StdIn, rkyv::rancor::Error> {
        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&self.block_witnesses)?;
        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);
        Ok(stdin)
    }
}
