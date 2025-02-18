use alloy_primitives::B256;
use openvm_sdk::StdIn;
use sbv::primitives::types::BlockWitness;
use scroll_zkvm_circuit_input_types::chunk::ChunkWitness;

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
    /// The on-chain L1 msg queue hash before applying L1 msg txs from the chunk.
    pub prev_msg_queue_hash: B256,
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
        let witness = ChunkWitness {
            blocks: self.block_witnesses.to_vec(),
            prev_msg_queue_hash: self.prev_msg_queue_hash,
        };
        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&witness)?;
        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);
        Ok(stdin)
    }
}
