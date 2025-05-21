use crate::{
    chunk::{
        ArchivedChunkWitness, ChunkInfo, CodeDb, ForkName, NodesProvider, make_providers,
        public_inputs::BlockContextV2,
    },
    manually_drop_on_zkvm,
};
use alloy_primitives::B256;
use sbv_core::{EvmDatabase, EvmExecutor};
use sbv_kv::null::NullProvider;
use sbv_primitives::{
    BlockWitness,
    chainspec::{
        BaseFeeParams, BaseFeeParamsKind, Chain, MAINNET,
        reth_chainspec::ChainSpec,
        scroll::{ScrollChainConfig, ScrollChainSpec},
    },
    ext::{BlockWitnessChunkExt, TxBytesHashExt},
    hardforks::SCROLL_DEV_HARDFORKS,
    types::{
        reth::{Block, BlockWitnessRethExt, RecoveredBlock},
        scroll::ChunkInfoBuilder,
    },
};
use std::{collections::BTreeMap, sync::Arc};

type Witness = ArchivedChunkWitness;

pub fn execute(witness: &Witness) -> Result<ChunkInfo, String> {
    if witness.blocks.is_empty() {
        return Err("At least one witness must be provided in chunk mode".into());
    }
    if !witness.blocks.has_same_chain_id() {
        return Err("All witnesses must have the same chain id in chunk mode".into());
    }
    if !witness.blocks.has_seq_block_number() {
        return Err("All witnesses must have sequential block numbers in chunk mode".into());
    }

    // Build ChainSpec
    let fork_name = ForkName::from(&witness.fork_name);
    let chain = Chain::from_id(witness.blocks[0].chain_id());
    let chain_spec = build_chain_spec_cheap(chain, fork_name);

    // Get prev_state_root and post_state_root
    let prev_state_root = witness.blocks[0].pre_state_root();
    let post_state_root = witness.blocks.last().unwrap().post_state_root();

    // Initialize the providers
    let providers = make_providers(&witness.blocks);

    // Get the blocks to build the basic chunk-info.
    let blocks = manually_drop_on_zkvm!(
        witness
            .blocks
            .iter()
            .map(|w| w.build_reth_block())
            .collect::<Result<Vec<RecoveredBlock<Block>>, _>>()
            .map_err(|e| e.to_string())?
    );

    let withdraw_root = if witness.batch_commit {
        execute_inner_batched(
            &providers,
            &blocks,
            chain_spec.clone(),
            prev_state_root,
            post_state_root,
        )?
    } else {
        execute_inner_block_by_block(&providers, &blocks, chain_spec.clone(), witness)?
    };

    let mut rlp_buffer = manually_drop_on_zkvm!(Vec::with_capacity(2048));
    let (tx_data_length, tx_data_digest): (usize, B256) = blocks
        .iter()
        .flat_map(|b| b.body().transactions.iter())
        .tx_bytes_hash_in(rlp_buffer.as_mut());

    let sbv_chunk_info = {
        let mut sbv_chunk_info_builder =
            ChunkInfoBuilder::new(&chain_spec, prev_state_root, &blocks);
        if fork_name == ForkName::EuclidV2 {
            sbv_chunk_info_builder.set_prev_msg_queue_hash(witness.prev_msg_queue_hash.into());
        }
        sbv_chunk_info_builder.build(withdraw_root)
    };

    let chunk_info = ChunkInfo {
        chain_id: chain.id(),
        prev_state_root,
        post_state_root,
        data_hash: sbv_chunk_info
            .clone()
            .into_legacy()
            .map(|x| x.data_hash)
            .unwrap_or_default(),
        withdraw_root,
        tx_data_digest,
        tx_data_length: tx_data_length as u64,
        initial_block_number: witness.blocks[0].number(),
        prev_msg_queue_hash: witness.prev_msg_queue_hash.into(),
        post_msg_queue_hash: sbv_chunk_info
            .into_euclid_v2()
            .map(|x| x.post_msg_queue_hash)
            .unwrap_or_default(),
        block_ctxs: blocks.iter().map(BlockContextV2::from).collect(),
    };

    openvm::io::println(format!("withdraw_root = {:?}", withdraw_root));
    openvm::io::println(format!("tx_bytes_hash = {:?}", tx_data_digest));

    // We should never touch that lazy lock... Or else we introduce 40M useless cycles.
    assert!(std::sync::LazyLock::get(&MAINNET).is_none());

    Ok(chunk_info)
}

#[inline(always)]
fn build_chain_spec_cheap(chain: Chain, fork_name: ForkName) -> Arc<ScrollChainSpec> {
    // SCROLL_DEV_HARDFORKS will enable all forks
    let mut hardforks = (*SCROLL_DEV_HARDFORKS).clone();
    if fork_name == ForkName::EuclidV1 {
        // disable EuclidV2 fork for legacy chunk
        use sbv_primitives::{chainspec::ForkCondition, hardforks::ScrollHardfork};
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
        // We cannot use `..Default::default()` here,
        // because it will trigger `MAINNET` genesis deserialization.
    };
    let config = ScrollChainConfig::mainnet();
    Arc::new(ScrollChainSpec { inner, config })
}

#[inline(always)]
fn execute_inner_batched(
    (code_db, nodes_provider): &(CodeDb, NodesProvider),
    blocks: &[RecoveredBlock<Block>],
    chain_spec: Arc<ScrollChainSpec>,
    prev_state_root: B256,
    post_state_root: B256,
) -> Result<B256, String> {
    let mut db = manually_drop_on_zkvm!(
        EvmDatabase::new_from_root(code_db, prev_state_root, nodes_provider, NullProvider)
            .map_err(|e| format!("failed to create EvmDatabase: {}", e))?
    );
    for block in blocks.iter() {
        let output = manually_drop_on_zkvm!(
            EvmExecutor::new(chain_spec.clone(), &db, block)
                .execute()
                .map_err(|e| format!("failed to execute block#{}: {}", block.number, e))?
        );
        // sort the update by key - Address in ascending order,
        // using reference to avoid cloning [`BundleAccount`].
        let state = manually_drop_on_zkvm!(BTreeMap::from_iter(output.state.state.iter()));
        db.update(nodes_provider, state.iter().map(|(k, v)| (*k, *v)))
            .map_err(|e| format!("failed to update db for block#{}: {}", block.number, e))?;
    }
    let db_post_state_root = db.commit_changes();
    if post_state_root != db_post_state_root {
        return Err(format!(
            "state root mismatch: expected={post_state_root}, found={db_post_state_root}"
        ));
    }
    let withdraw_root = db
        .withdraw_root()
        .map_err(|e| format!("failed to get withdraw root: {}", e))?;
    Ok(withdraw_root)
}

#[inline(always)]
fn execute_inner_block_by_block(
    (code_db, nodes_provider): &(CodeDb, NodesProvider),
    blocks: &[RecoveredBlock<Block>],
    chain_spec: Arc<ScrollChainSpec>,
    witness: &Witness,
) -> Result<B256, String> {
    let mut iter = blocks.iter().zip(witness.blocks.iter()).peekable();
    while let Some((block, witness)) = iter.next() {
        // We construct the merkle trie for each block, should have the same behavior as geth stateless.
        let mut db = manually_drop_on_zkvm!(
            EvmDatabase::new_from_root(
                code_db,
                witness.pre_state_root(),
                nodes_provider,
                NullProvider
            )
            .map_err(|e| format!(
                "failed to create EvmDatabase for block#{}: {}",
                block.number, e
            ))?
        );
        let output = manually_drop_on_zkvm!(
            EvmExecutor::new(chain_spec.clone(), &db, block)
                .execute()
                .map_err(|e| format!("failed to execute block#{}: {}", block.number, e))?
        );
        // sort the update by key - Address in ascending order,
        // using reference to avoid cloning [`BundleAccount`].
        let state = manually_drop_on_zkvm!(BTreeMap::from_iter(output.state.state.iter()));
        db.update(nodes_provider, state.iter().map(|(k, v)| (*k, *v)))
            .map_err(|e| format!("failed to update db for block#{}: {}", block.number, e))?;
        let post_state_root = db.commit_changes();
        // state root assertion happens for each block, instead of at the end.
        if witness.post_state_root() != post_state_root {
            return Err(format!(
                "state root mismatch for block#{}: expected={}, found={}",
                block.number,
                witness.post_state_root(),
                post_state_root
            ));
        }
        // We reach the last block, we can return the withdraw root.
        if iter.peek().is_none() {
            let withdraw_root = db
                .withdraw_root()
                .map_err(|e| format!("failed to get withdraw root: {}", e))?;
            return Ok(withdraw_root);
        }
    }
    unreachable!()
}
