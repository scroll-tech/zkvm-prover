use crate::{
    Error, Prover, ProverType,
    proof::{ChunkProofMetadata, RootProof},
    task::{ProvingTask, chunk::ChunkProvingTask},
};
use scroll_zkvm_circuit_input_types::chunk::{ArchivedChunkWitness, ChunkWitness, execute};

#[cfg(feature = "euclidv2")]
use crate::commitments::chunk::{EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT};
#[cfg(not(feature = "euclidv2"))]
use crate::commitments::chunk_legacy::{
    EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT,
};

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<ChunkProverType>;

pub struct ChunkProverType;

impl ProverType for ChunkProverType {
    const NAME: &'static str = "chunk";

    const EVM: bool = false;

    const SEGMENT_SIZE: usize = (1 << 22) - 100;

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

        let chunk_witness = ChunkWitness::new(&task.block_witnesses, task.prev_msg_queue_hash);
        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&chunk_witness).map_err(|e| {
            Error::GenProof(format!(
                "{}: failed to serialize chunk witness: {}",
                err_prefix, e
            ))
        })?;
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
