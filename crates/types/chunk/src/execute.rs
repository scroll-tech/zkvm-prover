use crate::{
    ArchivedChunkWitness, BlockHashProvider, CodeDb, NodesProvider, make_providers,
    manually_drop_on_zkvm, witness::ArchivedStateCommitMode,
};
use alloy_primitives::B256;
use itertools::Itertools;
use sbv_core::{EvmDatabase, EvmExecutor};
use sbv_primitives::{
    BlockWitness, U256,
    chainspec::{
        Chain,
        reth_chainspec::ChainSpec,
        scroll::{ScrollChainConfig, ScrollChainSpec},
    },
    ext::{BlockWitnessChunkExt, BlockWitnessRethExt as _, TxBytesHashExt},
    hardforks::SCROLL_DEV_HARDFORKS,
    types::{
        reth::primitives::{Block, RecoveredBlock},
        scroll::ChunkInfoBuilder,
    },
};
use std::sync::Arc;
use types_base::{fork_name::ForkName, public_inputs::chunk::ChunkInfo};

type Witness = ArchivedChunkWitness;

/// `compression_ratios` can be `None` in host mode.
/// But in guest mode, it must be provided.
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
    // Get the blocks to build the basic chunk-info.
    println!("#0000");
    let blocks = manually_drop_on_zkvm!(
        witness
            .blocks
            .iter()
            .map(|w| w.build_reth_block())
            .collect::<Result<Vec<RecoveredBlock<Block>>, _>>()
            .map_err(|e| e.to_string())?
    );
    let pre_state_root = witness.blocks[0].pre_state_root;

    let fork_name = ForkName::from(&witness.fork_name);
    let chain = Chain::from_id(witness.blocks[0].chain_id());

    // SCROLL_DEV_HARDFORKS will enable all forks
    let mut hardforks = (*SCROLL_DEV_HARDFORKS).clone();
    println!("#0001");
    use sbv_primitives::{chainspec::ForkCondition, hardforks::ScrollHardfork};
    if fork_name < ForkName::Feynman {
        hardforks.insert(ScrollHardfork::Feynman, ForkCondition::Never);
    }
    if fork_name < ForkName::EuclidV2 {
        hardforks.insert(ScrollHardfork::EuclidV2, ForkCondition::Never);
    }

    let inner = ChainSpec {
        chain,
        hardforks,
        ..Default::default()
    };
    let config = ScrollChainConfig::mainnet();
    let chain_spec = Arc::new(ScrollChainSpec { inner, config });

    println!("#0002");
    let (code_db, nodes_provider, block_hashes) = make_providers(&witness.blocks);
    let code_db = manually_drop_on_zkvm!(code_db);
    let nodes_provider = manually_drop_on_zkvm!(nodes_provider);

    let prev_state_root = witness.blocks[0].pre_state_root();

    let state_commit_mode = &witness.state_commit_mode;
    println!("state_commit_mode: {:?}", state_commit_mode);

    let compression_ratios = witness
        .compression_ratios
        .iter()
        .map(|b| b.iter().map(|c| c.into()).collect())
        .collect::<Vec<Vec<U256>>>();

    println!("#0003");
    let (post_state_root, withdraw_root) = match state_commit_mode {
        ArchivedStateCommitMode::Chunk | ArchivedStateCommitMode::Block => execute_inner(
            &code_db,
            &nodes_provider,
            &block_hashes,
            prev_state_root,
            &blocks,
            chain_spec.clone(),
            compression_ratios,
            matches!(state_commit_mode, ArchivedStateCommitMode::Chunk),
        )?,
        ArchivedStateCommitMode::Auto => match execute_inner(
            &code_db,
            &nodes_provider,
            &block_hashes,
            prev_state_root,
            &blocks,
            chain_spec.clone(),
            compression_ratios.clone(),
            true,
        ) {
            Ok((post_state_root, withdraw_root)) => (post_state_root, withdraw_root),
            Err(e) if e.starts_with("failed to update db:") => {
                openvm::io::println(format!("{e}; retrying with defer commit disabled"));
                execute_inner(
                    &code_db,
                    &nodes_provider,
                    &block_hashes,
                    prev_state_root,
                    &blocks,
                    chain_spec.clone(),
                    compression_ratios,
                    false,
                )?
            }
            Err(e) => return Err(e),
        },
    };

    println!("#0100");
    let mut rlp_buffer = manually_drop_on_zkvm!(Vec::with_capacity(2048));
    let (tx_data_length, tx_data_digest) = blocks
        .iter()
        .flat_map(|b| b.body().transactions.iter())
        .tx_bytes_hash_in(rlp_buffer.as_mut());

    let sbv_chunk_info = {
        #[allow(unused_mut)]
        let mut builder = ChunkInfoBuilder::new(&chain_spec, pre_state_root.into(), &blocks);
        if fork_name >= ForkName::EuclidV2 {
            builder.set_prev_msg_queue_hash(witness.prev_msg_queue_hash.into());
        }
        builder.build(withdraw_root)
    };
    println!("#0101");
    if post_state_root != sbv_chunk_info.post_state_root() {
        return Err(format!(
            "state root mismatch: expected={}, found={}",
            sbv_chunk_info.post_state_root(),
            post_state_root
        ));
    }

    let chunk_info = ChunkInfo {
        chain_id: sbv_chunk_info.chain_id(),
        prev_state_root: sbv_chunk_info.prev_state_root(),
        post_state_root: sbv_chunk_info.post_state_root(),
        data_hash: sbv_chunk_info
            .clone()
            .into_legacy()
            .map(|x| x.data_hash)
            .unwrap_or_default(),
        withdraw_root,
        tx_data_digest,
        tx_data_length: u64::try_from(tx_data_length).expect("tx_data_length: u64"),
        initial_block_number: blocks[0].header().number,
        prev_msg_queue_hash: witness.prev_msg_queue_hash.into(),
        post_msg_queue_hash: sbv_chunk_info
            .into_euclid_v2()
            .map(|x| x.post_msg_queue_hash)
            .unwrap_or_default(),
        block_ctxs: blocks.iter().map(Into::into).collect(),
    };

    println!("#0102");
    openvm::io::println(format!("withdraw_root = {:?}", withdraw_root));
    openvm::io::println(format!("tx_bytes_hash = {:?}", tx_data_digest));

    Ok(chunk_info)
}

#[allow(clippy::too_many_arguments)]
fn execute_inner(
    code_db: &CodeDb,
    nodes_provider: &NodesProvider,
    block_hashes: &BlockHashProvider,
    prev_state_root: B256,
    blocks: &[RecoveredBlock<Block>],
    chain_spec: Arc<ScrollChainSpec>,
    compression_ratios: Vec<Vec<U256>>,
    defer_commit: bool,
) -> Result<(B256, B256), String> {
    let mut db = manually_drop_on_zkvm!(
        EvmDatabase::new_from_root(code_db, prev_state_root, nodes_provider, block_hashes)
            .map_err(|e| format!("failed to create EvmDatabase: {}", e))?
    );
    println!("#0004");
    for (block, compression_ratios) in blocks.iter().zip_eq(compression_ratios.into_iter()) {
        let output = manually_drop_on_zkvm!(
            EvmExecutor::new(chain_spec.clone(), &db, block, Some(compression_ratios))
                .execute()
                .map_err(|e| format!("failed to execute block: {}", e))?
        );
        println!("#0005");
        db.update(nodes_provider, output.state.state.iter())
            .map_err(|e| format!("failed to update db: {}", e))?;
        println!("#0006");
        if !defer_commit {
            db.commit_changes();
        }
        println!("#0007");
    }
    let post_state_root = db.commit_changes();
    println!("#0008");
    let withdraw_root = db
        .withdraw_root()
        .map_err(|e| format!("failed to get withdraw root: {}", e))?;
    Ok((post_state_root, withdraw_root))
}
