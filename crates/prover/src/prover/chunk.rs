use scroll_zkvm_circuit_input_types::chunk::{ArchivedChunkWitness, ChunkWitness, execute};

use crate::{
    Error, Prover, ProverType,
    commitments::chunk::{EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT},
    proof::{ChunkProofMetadata, RootProof},
    task::{ProvingTask, chunk::ChunkProvingTask},
};

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<ChunkProverType>;

pub struct ChunkProverType;

impl ProverType for ChunkProverType {
    const NAME: &'static str = "chunk";

    const EVM: bool = false;

    const SEGMENT_SIZE: usize = 8388508;

    const EXE_COMMIT: [u32; 8] = CHUNK_EXE_COMMIT;

    const LEAF_COMMIT: [u32; 8] = CHUNK_LEAF_COMMIT;

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
        // We want to reuse codes as much as possible, so we serialize the chunk witness
        // and execute it with "ArchivedChunkWitness".
        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&chunk_witness).map_err(|e| {
            Error::GenProof(format!(
                "{err_prefix}: failed to serialize chunk witness: {e}"
            ))
        })?;
        let chunk_witness = rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(
            &serialized,
        )
        .map_err(|e| {
            Error::GenProof(format!(
                "{err_prefix}: rkyv deserialisation of chunk witness bytes failed: {e}",
            ))
        })?;

        let chunk_info =
            execute(chunk_witness).map_err(|e| Error::GenProof(format!("{err_prefix}: {e}")))?;

        Ok(ChunkProofMetadata { chunk_info })
    }
}
