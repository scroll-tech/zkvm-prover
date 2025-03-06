use sbv::{
    core::{EvmDatabase, EvmExecutor},
    primitives::{
        chainspec::{
            BaseFeeParams, BaseFeeParamsKind, Chain,
            reth_chainspec::ChainSpec,
            scroll::{ScrollChainConfig, ScrollChainSpec},
        },
        ext::TxBytesHashExt,
        hardforks::SCROLL_DEV_HARDFORKS,
        types::ChunkInfoBuilder,
    },
};
use scroll_zkvm_circuit_input_types::chunk::{ChunkInfo, make_providers};

#[cfg(feature = "scroll")]
use sbv::primitives::{BlockWitness, RecoveredBlock, types::reth::Block};

use crate::{
    Error,
    commitments::chunk::{EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT},
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

    const EXE_COMMIT: [u32; 8] = CHUNK_EXE_COMMIT;

    const LEAF_COMMIT: [u32; 8] = CHUNK_LEAF_COMMIT;

    type ProvingTask = ChunkProvingTask;

    type ProofType = RootProof;

    type ProofMetadata = ChunkProofMetadata;

    fn read_app_config<P: AsRef<std::path::Path>>(
        path_app_config: P,
    ) -> Result<openvm_sdk::config::AppConfig<openvm_sdk::config::SdkVmConfig>, Error> {
        let mut config = read_app_config(path_app_config)?;
        config.app_vm_config.system.config = config
            .app_vm_config
            .system
            .config
            .with_max_segment_len((1 << 22) - 100);
        Ok(config)
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
        let blocks = task
            .block_witnesses
            .iter()
            .map(|s| s.build_reth_block())
            .collect::<Result<Vec<RecoveredBlock<Block>>, _>>()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        let prev_state_root = first_block.pre_state_root();

        let chain = Chain::from_id(first_block.chain_id());

        // enable all forks
        #[allow(unused_mut)]
        let mut hardforks = (*SCROLL_DEV_HARDFORKS).clone();
        // disable EuclidV2 if not configured
        {
            use sbv::primitives::{chainspec::ForkCondition, hardforks::ScrollHardfork};
            hardforks.insert(ScrollHardfork::EuclidV2, ForkCondition::Never);
        }

        let inner = ChainSpec {
            chain,
            genesis_hash: Default::default(),
            genesis: Default::default(),
            genesis_header: Default::default(),
            paris_block_and_final_difficulty: Default::default(),
            hardforks,
            deposit_contract: Default::default(),
            base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
            prune_delete_limit: 20000,
            blob_params: Default::default(),
        };
        let config = ScrollChainConfig::mainnet();
        let chain_spec: ScrollChainSpec = ScrollChainSpec { inner, config };

        let (code_db, nodes_provider, block_hashes) = make_providers(&task.block_witnesses);

        let mut db =
            EvmDatabase::new_from_root(code_db, prev_state_root, &nodes_provider, block_hashes)
                .map_err(|e| {
                    Error::GenProof(format!("{err_prefix}: failed to create EvmDatabase: {}", e,))
                })?;

        for block in blocks.iter() {
            let output = EvmExecutor::new(std::sync::Arc::new(chain_spec.clone()), &db, block)
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

        let sbv_chunk_info = {
            #[allow(unused_mut)]
            let mut builder = ChunkInfoBuilder::new(&chain_spec, prev_state_root, &blocks);
            builder.build(withdraw_root)
        };

        if post_state_root != sbv_chunk_info.post_state_root() {
            return Err(Error::GenProof(format!(
                "{err_prefix}: state root mismatch: expected={}, found={}",
                sbv_chunk_info.post_state_root(),
                post_state_root
            )));
        }

        let mut rlp_buffer = Vec::with_capacity(2048);
        let (_, tx_data_digest) = blocks
            .iter()
            .flat_map(|b| b.body().transactions.iter())
            .tx_bytes_hash_in(rlp_buffer.as_mut());

        let chunk_info = ChunkInfo {
            chain_id: sbv_chunk_info.chain_id(),
            prev_state_root: sbv_chunk_info.prev_state_root(),
            post_state_root: sbv_chunk_info.post_state_root(),
            withdraw_root,
            data_hash: sbv_chunk_info
                .into_legacy()
                .expect("legacy chunk")
                .data_hash,
            tx_data_digest,
        };

        let num_txs = blocks
            .iter()
            .map(|b| b.body().transactions.len())
            .sum::<usize>();
        let total_gas_used = blocks.iter().map(|b| b.header().gas_used).sum::<u64>();

        tracing::debug!(name: "chunk details", num_blocks = ?blocks.len(), ?num_txs, ?total_gas_used);

        Ok(ChunkProofMetadata { chunk_info })
    }
}
