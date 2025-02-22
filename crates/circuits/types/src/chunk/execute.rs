use std::mem::ManuallyDrop;

use crate::chunk::{ArchivedChunkWitness, ChunkInfo, ChunkWitness, make_providers};
use sbv::{
    core::{EvmDatabase, EvmExecutor},
    primitives::{
        BlockWitness, RecoveredBlock,
        chainspec::{Chain, ForkCondition, get_chain_spec_or_build, scroll::ScrollChainSpec},
        ext::{BlockWitnessChunkExt, TxBytesHashExt},
        hardforks::{SCROLL_DEV_HARDFORKS, ScrollHardfork},
        types::{ChunkInfoBuilder, reth::Block},
    },
};

#[cfg(feature = "euclidv2")]
use crate::chunk::public_inputs_euclidv2::BlockContextV2;

#[cfg(feature = "bincode")]
type Witness = ChunkWitness;
#[cfg(not(feature = "bincode"))]
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
    // Get the blocks to build the basic chunk-info.
    let blocks = witness
        .blocks
        .iter()
        .map(|w| w.build_reth_block())
        .collect::<Result<Vec<RecoveredBlock<Block>>, _>>()
        .map_err(|e| e.to_string())?;
    //#[cfg(target_os = "zkvm")]
    let blocks = blocks.leak() as &'static [RecoveredBlock<Block>];
    let pre_state_root = witness.blocks[0].pre_state_root;

    let mut chain_spec: ScrollChainSpec =
        (*get_chain_spec_or_build(Chain::from_id(witness.blocks[0].chain_id()), |_| {})).clone();
    // enable all forks
    chain_spec.inner.hardforks = (*SCROLL_DEV_HARDFORKS).clone();
    // disable EuclidV2 if not configured
    #[cfg(not(feature = "euclidv2"))]
    chain_spec
        .inner
        .hardforks
        .insert(ScrollHardfork::EuclidV2, ForkCondition::Never);

    let (code_db, nodes_provider, block_hashes) = make_providers(&witness.blocks);
    let mut nodes_provider = ManuallyDrop::new(nodes_provider);

    let prev_state_root = witness.blocks[0].pre_state_root();
    let mut db = ManuallyDrop::new(
        EvmDatabase::new_from_root(code_db, prev_state_root, &nodes_provider, block_hashes)
            .map_err(|e| format!("failed to create EvmDatabase: {}", e))?,
    );
    let mut outputs = Vec::new();
    for block in blocks.iter() {
        let output = ManuallyDrop::new(
            EvmExecutor::new(std::sync::Arc::new(chain_spec.clone()), &db, block)
                .execute()
                .map_err(|e| format!("failed to execute block: {}", e))?,
        );
        db.update(&nodes_provider, output.state.state.iter())
            .map_err(|e| format!("failed to update db: {}", e))?;
        outputs.push(output);
    }

    let post_state_root = db.commit_changes();

    let withdraw_root = db
        .withdraw_root()
        .map_err(|e| format!("failed to get withdraw root: {}", e))?;

    let mut rlp_buffer = ManuallyDrop::new(Vec::with_capacity(2048));
    #[allow(unused_variables)]
    let (tx_data_length, tx_data_digest) = blocks
        .iter()
        .flat_map(|b| b.body().transactions.iter())
        .tx_bytes_hash_in(rlp_buffer.as_mut());

    let sbv_chunk_info = {
        #[allow(unused_mut)]
        let mut builder = ChunkInfoBuilder::new(&chain_spec, pre_state_root.into(), &blocks);
        #[cfg(feature = "euclidv2")]
        builder.set_prev_msg_queue_hash(witness.prev_msg_queue_hash.into());
        builder.build(withdraw_root)
    };
    if post_state_root != sbv_chunk_info.post_state_root() {
        return Err(format!(
            "state root mismatch: expected={}, found={}",
            sbv_chunk_info.post_state_root(),
            post_state_root
        ));
    }

    // TODO: unify this inside sbv
    #[cfg(feature = "euclidv2")]
    let chunk_info = ChunkInfo {
        chain_id: sbv_chunk_info.chain_id(),
        prev_state_root: sbv_chunk_info.prev_state_root(),
        post_state_root: sbv_chunk_info.post_state_root(),
        withdraw_root,
        tx_data_digest,
        tx_data_length: u64::try_from(tx_data_length).expect("tx_data_length: u64"),
        initial_block_number: blocks[0].header().number,
        prev_msg_queue_hash: witness.prev_msg_queue_hash.into(),
        post_msg_queue_hash: sbv_chunk_info
            .into_euclid_v2()
            .expect("euclid-v2")
            .post_msg_queue_hash,
        block_ctxs: blocks.iter().map(BlockContextV2::from).collect(),
    };
    #[cfg(not(feature = "euclidv2"))]
    let chunk_info = ChunkInfo {
        chain_id: sbv_chunk_info.chain_id(),
        prev_state_root: sbv_chunk_info.prev_state_root(),
        post_state_root: sbv_chunk_info.post_state_root(),
        withdraw_root,
        tx_data_digest,
        data_hash: sbv_chunk_info
            .into_legacy()
            .expect("legacy chunk")
            .data_hash,
    };

    openvm::io::println(format!("withdraw_root = {:?}", withdraw_root));
    openvm::io::println(format!("tx_bytes_hash = {:?}", tx_data_digest));

    #[cfg(not(target_os = "zkvm"))]
    {
        unsafe {
            ManuallyDrop::drop(&mut rlp_buffer);
            for mut output in outputs {
                ManuallyDrop::drop(&mut output);
            }
            ManuallyDrop::drop(&mut db);
            ManuallyDrop::drop(&mut nodes_provider);
        }
    }
    Ok(chunk_info)
}
