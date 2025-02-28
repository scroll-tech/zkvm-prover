use crate::{
    Error,
    proof::{ChunkProofMetadata, RootProof},
    setup::read_app_config,
    task::{ProvingTask, chunk::ChunkProvingTask},
};
use scroll_zkvm_circuit_input_types::chunk::{ArchivedChunkWitness, ChunkWitness, execute};

use crate::{Prover, ProverType};

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<ChunkProverType>;

pub struct ChunkProverType;

impl ProverType for ChunkProverType {
    const NAME: &'static str = "chunk";

    const EVM: bool = false;

    const SEGMENT_SIZE: usize = 8388508;

    type ProvingTask = ChunkProvingTask;

    type ProofType = RootProof;

    type ProofMetadata = ChunkProofMetadata;

    fn metadata_with_prechecks(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        let err_prefix = format!(
            "metadata_with_prechecks for task_id={:?}",
            task.identifier()
        );

        if task.block_witnesses.is_empty() {
            return Err(Error::GenProof(format!(
                "{err_prefix}: chunk should contain at least one block",
            )));
        }

        let chunk_witness = ChunkWitness {
            blocks: task.block_witnesses.to_vec(),
            prev_msg_queue_hash: task.prev_msg_queue_hash,
        };
        #[cfg(feature = "bincode")]
        let chunk_witness = &chunk_witness;
        #[cfg(not(feature = "bincode"))]
        // We want to reuse codes as much as possible, so we serialize the chunk witness
        // and execute it with "ArchivedChunkWitness".
        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&chunk_witness).map_err(|e| {
            Error::GenProof(format!(
                "{}: failed to serialize chunk witness: {}",
                err_prefix, e
            ))
        })?;
        #[cfg(not(feature = "bincode"))]
        let chunk_witness = rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(
            &serialized,
        )
        .map_err(|e| {
            Error::GenProof(format!(
                "{}: rkyv deserialisation of chunk witness bytes failed: {}",
                err_prefix, e
            ))
        })?;

        let chunk_info = execute(chunk_witness)
            .map_err(|e| Error::GenProof(format!("{}: {}", err_prefix, e)))?;

        Ok(ChunkProofMetadata { chunk_info })
    }
}
