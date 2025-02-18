use sbv::{
    core::{EvmDatabase, EvmExecutor},
    primitives::{
        chainspec::{Chain, get_chain_spec},
        ext::TxBytesHashExt,
    },
};
use scroll_zkvm_circuit_input_types::chunk::{BlockContextV2, ChunkInfo, make_providers};

#[cfg(feature = "scroll")]
use sbv::primitives::{
    BlockWitness, RecoveredBlock,
    types::{ChunkInfoBuilder, reth::Block},
};

use crate::{
    Error,
    proof::{ChunkProofMetadata, RootProof},
    setup::read_app_config,
    task::{ProvingTask, chunk::ChunkProvingTask},
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

    fn read_app_config<P: AsRef<std::path::Path>>(
        path_app_config: P,
    ) -> Result<openvm_sdk::config::AppConfig<openvm_sdk::config::SdkVmConfig>, Error> {
        read_app_config(path_app_config)
    }

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

        let first_block = task
            .block_witnesses
            .first()
            .expect("at least one block in a chunk");

        // Get the blocks to build the basic chunk-info.
        let chain_id = first_block.chain_id;
        let blocks = task
            .block_witnesses
            .iter()
            .map(|s| s.build_reth_block())
            .collect::<Result<Vec<RecoveredBlock<Block>>, _>>()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        let chain_spec = get_chain_spec(Chain::from_id(task.block_witnesses[0].chain_id())).ok_or(
            Error::GenProof(format!("{err_prefix}: failed to get chain spec")),
        )?;

        let (code_db, nodes_provider, block_hashes) = make_providers(&task.block_witnesses);

        let mut db = EvmDatabase::new_from_root(
            code_db,
            task.block_witnesses[0].pre_state_root,
            &nodes_provider,
            block_hashes,
        )
        .map_err(|e| {
            Error::GenProof(format!("{err_prefix}: failed to create EvmDatabase: {}", e,))
        })?;

        for block in blocks.iter() {
            let output = EvmExecutor::new(chain_spec.clone(), &db, block)
                .execute()
                .map_err(|e| {
                    Error::GenProof(format!("{err_prefix}: failed to execute block: {}", e,))
                })?;

            db.update(&nodes_provider, output.state.state.iter())
                .map_err(|e| {
                    Error::GenProof(format!("{err_prefix}: failed to update db: {}", e,))
                })?;
        }

        let post_state_root = db.commit_changes();

        let withdraw_root = db.withdraw_root().map_err(|e| {
            Error::GenProof(format!(
                "{err_prefix}: failed to get withdrawals root: {}",
                e,
            ))
        })?;

        let mut rlp_buffer = Vec::with_capacity(2048);
        let (tx_data_length, tx_data_digest) = blocks
            .iter()
            .flat_map(|b| b.body().transactions.iter())
            .tx_bytes_hash_in(rlp_buffer.as_mut());

        let block_ctxs = blocks.iter().map(BlockContextV2::from).collect();

        let sbv_chunk_info = {
            let mut builder = ChunkInfoBuilder::new(&chain_spec, &blocks);
            builder.prev_msg_queue_hash(task.prev_msg_queue_hash);
            builder
                .build(withdraw_root)
                .into_euclid_v2()
                .expect("euclid-v2")
        };
        if post_state_root != sbv_chunk_info.post_state_root {
            return Err(Error::GenProof(format!(
                "{err_prefix}: state root mismatch: expected={}, found={}",
                sbv_chunk_info.post_state_root, post_state_root
            )));
        }

        let chunk_info = ChunkInfo {
            chain_id: sbv_chunk_info.chain_id,
            prev_state_root: sbv_chunk_info.prev_state_root,
            post_state_root: sbv_chunk_info.post_state_root,
            withdraw_root,
            tx_data_digest,
            tx_data_length: u64::try_from(tx_data_length).expect("tx_data_length: u64"),
            prev_msg_queue_hash: task.prev_msg_queue_hash,
            post_msg_queue_hash: sbv_chunk_info.post_msg_queue_hash,
            block_ctxs,
        };

        Ok(ChunkProofMetadata { chunk_info })
    }
}
