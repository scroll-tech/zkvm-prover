#![no_main]

use itertools::Itertools;
use profile_lib::*;
use sbv_core::{EvmDatabase, EvmExecutor};
use sbv_kv::nohash::NoHashMap;
use sbv_primitives::{
    Address, B256, BlockWitness as _, Bytes, U256,
    alloy_primitives::map::HashMap,
    chainspec::{
        Chain,
        reth_chainspec::ChainSpec,
        scroll::{ScrollChainConfig, ScrollChainSpec},
    },
    ext::{BlockWitnessChunkExt, BlockWitnessExt, BlockWitnessRethExt, TxBytesHashExt},
    hardforks::SCROLL_DEV_HARDFORKS,
    types::{
        ArchivedBlockWitness,
        reth::{
            execution_types::BlockExecutionOutput,
            primitives::{Block, Receipt, RecoveredBlock},
        },
        revm::database::BundleAccount,
        scroll::ChunkInfoBuilder,
    },
};
use sbv_trie::{BlockWitnessTrieExt, TrieNode};
use scroll_zkvm_types_base::{fork_name::ForkName, public_inputs::chunk::ChunkInfo};
use sp1_zkvm::lib::{syscall_hint_len, syscall_hint_read};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::BTreeMap,
    slice::from_raw_parts,
    sync::Arc,
};

sp1_zkvm::entrypoint!(main);

macro_rules! manually_drop_on_zkvm {
    ($e:expr) => {
        std::mem::ManuallyDrop::new($e)
    };
}

#[inline(never)]
fn main() {
    let witness_bytes = read_witness();
    let witness = access_witness(witness_bytes);
    execute(witness).expect("failed to execute chunk");
}

#[inline(never)]
fn read_witness() -> &'static [u8] {
    let len = unsafe { syscall_hint_len() };
    // rkyv needs special alignment for its data structures
    let layout = Layout::from_size_align(len, 16).unwrap();
    unsafe {
        let ptr = System.alloc(layout);
        syscall_hint_read(ptr, len);
        from_raw_parts(ptr, len)
    }
}

#[inline(never)]
fn access_witness(witness_bytes: &[u8]) -> &ArchivedChunkWitness {
    rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(witness_bytes)
        .expect("ChunkCircuit: rkyv deserialisation of witness bytes failed")
}

#[inline(never)]
fn pre_check(witness: &ArchivedChunkWitness) -> Result<(), String> {
    if witness.blocks.is_empty() {
        return Err("At least one witness must be provided in chunk mode".into());
    }
    if !witness.blocks.has_same_chain_id() {
        return Err("All witnesses must have the same chain id in chunk mode".into());
    }
    if !witness.blocks.has_seq_block_number() {
        return Err("All witnesses must have sequential block numbers in chunk mode".into());
    }
    Ok(())
}

#[inline(never)]
fn build_reth_blocks(witness: &ArchivedChunkWitness) -> Result<Vec<RecoveredBlock<Block>>, String> {
    witness
        .blocks
        .iter()
        .map(|w| w.build_reth_block())
        .collect::<Result<Vec<RecoveredBlock<Block>>, _>>()
        .map_err(|e| e.to_string())
}

#[inline(never)]
fn make_chain_spec(chain: Chain, fork_name: ForkName) -> Arc<ScrollChainSpec> {
    use sbv_primitives::{chainspec::ForkCondition, hardforks::ScrollHardfork};

    // SCROLL_DEV_HARDFORKS will enable all forks
    let mut hardforks = (*SCROLL_DEV_HARDFORKS).clone();
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
    Arc::new(ScrollChainSpec { inner, config })
}

#[inline(never)]
fn make_code_db(witnesses: &[ArchivedBlockWitness]) -> CodeDb {
    // build code db
    let num_codes = witnesses.iter().map(|w| w.codes_iter().len()).sum();
    let mut code_db =
        NoHashMap::<B256, Bytes>::with_capacity_and_hasher(num_codes, Default::default());
    witnesses.import_codes(&mut code_db);
    code_db
}

#[inline(never)]
fn make_nodes_provider(witnesses: &[ArchivedBlockWitness]) -> NodesProvider {
    let num_states = witnesses.iter().map(|w| w.states_iter().len()).sum();
    let mut nodes_provider =
        NoHashMap::<B256, TrieNode>::with_capacity_and_hasher(num_states, Default::default());
    witnesses.import_nodes(&mut nodes_provider).unwrap();
    nodes_provider
}

#[inline(never)]
fn make_providers(
    witnesses: &[ArchivedBlockWitness],
) -> (CodeDb, NodesProvider, BlockHashProvider) {
    let code_db = make_code_db(witnesses);
    let nodes_provider = make_nodes_provider(witnesses);
    let block_hashes = sbv_kv::null::NullProvider;
    (code_db, nodes_provider, block_hashes)
}

#[inline(never)]
fn collect_compression_ratios(witness: &ArchivedChunkWitness) -> Vec<Vec<U256>> {
    witness
        .compression_ratios
        .iter()
        .map(|b| b.iter().map(|c| c.into()).collect())
        .collect::<Vec<Vec<U256>>>()
}

#[inline(never)]
fn create_evm_db<'a>(
    code_db: &'a CodeDb,
    prev_state_root: B256,
    nodes_provider: &'a NodesProvider,
    block_hashes: &'a BlockHashProvider,
) -> Result<EvmDatabase<&'a CodeDb, &'a NodesProvider, &'a BlockHashProvider>, String> {
    EvmDatabase::new_from_root(code_db, prev_state_root, nodes_provider, block_hashes)
        .map_err(|e| format!("failed to create EvmDatabase: {}", e))
}

#[inline(never)]
fn execute_block(
    chain_spec: Arc<ScrollChainSpec>,
    db: &EvmDatabase<&CodeDb, &NodesProvider, &BlockHashProvider>,
    block: &RecoveredBlock<Block>,
    compression_ratios: Vec<U256>,
) -> Result<BlockExecutionOutput<Receipt>, String> {
    EvmExecutor::new(chain_spec, &db, block, Some(compression_ratios))
        .execute()
        .map_err(|e| format!("failed to execute block: {}", e))
}

#[inline(never)]
fn update_db(
    db: &mut EvmDatabase<&CodeDb, &NodesProvider, &BlockHashProvider>,
    nodes_provider: &NodesProvider,
    state: HashMap<Address, BundleAccount>,
) -> Result<(), String> {
    db.update(nodes_provider, BTreeMap::from_iter(state).iter())
        .map_err(|e| format!("failed to update db: {}", e))
}

#[inline(never)]
fn commit_db(db: &mut EvmDatabase<&CodeDb, &NodesProvider, &BlockHashProvider>) -> B256 {
    db.commit_changes()
}

#[inline(never)]
fn get_withdraw_root(
    db: &EvmDatabase<&CodeDb, &NodesProvider, &BlockHashProvider>,
) -> Result<B256, String> {
    db.withdraw_root()
        .map_err(|e| format!("failed to get withdraw root: {}", e))
}

#[inline(never)]
fn calc_tx_bytes_hash(blocks: &[RecoveredBlock<Block>]) -> (usize, B256) {
    let mut rlp_buffer = manually_drop_on_zkvm!(Vec::with_capacity(2048));
    blocks
        .iter()
        .flat_map(|b| b.body().transactions.iter())
        .tx_bytes_hash_in(rlp_buffer.as_mut())
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn build_sbv_chunk_info(
    chain_spec: &ScrollChainSpec,
    fork_name: ForkName,
    blocks: &[RecoveredBlock<Block>],
    pre_state_root: B256,
    prev_msg_queue_hash: B256,
    withdraw_root: B256,
) -> sbv_primitives::types::scroll::ChunkInfo {
    let mut builder = ChunkInfoBuilder::new(chain_spec, pre_state_root, &blocks);
    if fork_name >= ForkName::EuclidV2 {
        builder.set_prev_msg_queue_hash(prev_msg_queue_hash);
    }
    builder.build(withdraw_root)
}

#[inline(never)]
pub fn execute(witness: &ArchivedChunkWitness) -> Result<ChunkInfo, String> {
    pre_check(witness)?;

    // Get the blocks to build the basic chunk-info.
    let blocks = manually_drop_on_zkvm!(build_reth_blocks(witness)?);

    let pre_state_root = witness.blocks[0].pre_state_root;
    let fork_name = ForkName::from(&witness.fork_name);
    let chain = Chain::from_id(witness.blocks[0].chain_id());

    let chain_spec = make_chain_spec(chain, fork_name);

    let (code_db, nodes_provider, block_hashes) = make_providers(&witness.blocks);
    let code_db = manually_drop_on_zkvm!(code_db);
    let nodes_provider = manually_drop_on_zkvm!(nodes_provider);

    let prev_state_root = witness.blocks[0].pre_state_root();

    let state_commit_mode = &witness.state_commit_mode;

    let compression_ratios = collect_compression_ratios(&witness);

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
            Err(e) if e.starts_with("failed to update db:") => execute_inner(
                &code_db,
                &nodes_provider,
                &block_hashes,
                prev_state_root,
                &blocks,
                chain_spec.clone(),
                compression_ratios,
                false,
            )?,
            Err(e) => return Err(e),
        },
    };

    let (tx_data_length, tx_data_digest) = calc_tx_bytes_hash(&blocks);

    let sbv_chunk_info = build_sbv_chunk_info(
        &chain_spec,
        fork_name,
        &blocks,
        pre_state_root.into(),
        witness.prev_msg_queue_hash.into(),
        withdraw_root,
    );
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
    let mut db = manually_drop_on_zkvm!(create_evm_db(
        code_db,
        prev_state_root,
        nodes_provider,
        block_hashes
    )?);
    for (block, compression_ratios) in blocks.iter().zip_eq(compression_ratios.into_iter()) {
        let output = execute_block(chain_spec.clone(), &db, block, compression_ratios)?;
        update_db(&mut db, nodes_provider, output.state.state)?;
        if !defer_commit {
            commit_db(&mut db);
        }
    }
    let post_state_root = commit_db(&mut db);
    let withdraw_root = db
        .withdraw_root()
        .map_err(|e| format!("failed to get withdraw root: {}", e))?;
    Ok((post_state_root, withdraw_root))
}
