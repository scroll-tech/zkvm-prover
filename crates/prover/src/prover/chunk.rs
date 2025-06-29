use scroll_zkvm_types::chunk::{ChunkWitness, ToArchievedWitness, execute};

use crate::{
    Error, Prover, ProverType,
    commitments::{chunk, chunk_rv32},
    proof::ChunkProofMetadata,
    task::{ProvingTask, chunk::ChunkProvingTask},
};

use super::Commitments;

pub struct ChunkCircuit;
pub struct ChunkCircuitRv32;

impl Commitments for ChunkCircuit {
    const EXE_COMMIT: [u32; 8] = chunk::EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = chunk::LEAF_COMMIT;
}

impl Commitments for ChunkCircuitRv32 {
    const EXE_COMMIT: [u32; 8] = chunk_rv32::EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = chunk_rv32::LEAF_COMMIT;
}

pub type ChunkProverType = GenericChunkProverType<ChunkCircuit>;
pub type ChunkProverTypeRv32 = GenericChunkProverType<ChunkCircuitRv32>;

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<ChunkProverType>;
#[allow(dead_code)]
pub type ChunkProverRv32 = Prover<ChunkProverTypeRv32>;

pub struct GenericChunkProverType<C: Commitments>(std::marker::PhantomData<C>);

impl<C: Commitments> ProverType for GenericChunkProverType<C> {
    const NAME: &'static str = "chunk";

    const EVM: bool = false;

    const SEGMENT_SIZE: usize = (1 << 22) - 100;

    const EXE_COMMIT: [u32; 8] = C::EXE_COMMIT;

    const LEAF_COMMIT: [u32; 8] = C::LEAF_COMMIT;

    type ProvingTask = ChunkProvingTask;

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

        let chunk_witness = ChunkWitness::new(
            &task.block_witnesses,
            task.prev_msg_queue_hash,
            task.fork_name.as_str().into(),
        );

        let to_archieve = ToArchievedWitness::create(&chunk_witness).map_err(Error::GenProof)?;
        let chunk_info = execute(to_archieve.access().map_err(Error::GenProof)?, None)
            .map_err(|e| Error::GenProof(format!("{}: {}", err_prefix, e)))?;

        Ok(ChunkProofMetadata { chunk_info })
    }
}
