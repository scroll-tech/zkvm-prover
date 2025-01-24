use scroll_zkvm_circuit_input_types::chunk::ChunkInfo;

#[cfg(feature = "scroll")]
use sbv::{
    core::ChunkInfo as SbvChunkInfo,
    primitives::{BlockWithSenders, BlockWitness},
};

use crate::{
    Error,
    proof::{ChunkProofMetadata, RootProof},
    task::chunk::ChunkProvingTask,
};

use crate::{Prover, ProverType};

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<ChunkProverType>;

pub struct ChunkProverType;

impl ProverType for ChunkProverType {
    const NAME: &'static str = "chunk";

    const EVM: bool = false;

    type ProvingTask = ChunkProvingTask;

    type ProofType = RootProof;

    type ProofMetadata = ChunkProofMetadata;

    fn build_proof_metadata(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        let (first, last) = (
            task.block_witnesses
                .first()
                .expect("at least one block in a chunk"),
            task.block_witnesses
                .last()
                .expect("at least one block in a chunk"),
        );
        let withdraw_root = last.withdrawals_root();
        let sbv_chunk_info = {
            let chain_id = first.chain_id;
            let pre_state_root = first.pre_state_root;
            let blocks = task
                .block_witnesses
                .iter()
                .map(|s| s.build_reth_block())
                .collect::<Result<Vec<BlockWithSenders>, _>>()
                .map_err(|e| Error::GenProof(e.to_string()))?;
            SbvChunkInfo::from_blocks_iter(
                chain_id,
                pre_state_root,
                blocks.iter().map(|b| &b.block),
            )
        };
        let chunk_info = ChunkInfo {
            chain_id: sbv_chunk_info.chain_id(),
            prev_state_root: sbv_chunk_info.prev_state_root(),
            post_state_root: sbv_chunk_info.post_state_root(),
            withdraw_root,
            data_hash: sbv_chunk_info.data_hash(),
        };
        Ok(ChunkProofMetadata { chunk_info })
    }
}
