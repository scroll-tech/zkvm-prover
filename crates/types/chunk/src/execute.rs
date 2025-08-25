use crate::{ChunkWitness, types::ChunkExt};
use sbv_core::verifier::{self, VerifyResult};
use sbv_helpers::manually_drop_on_zkvm;
use sbv_primitives::{
    B256, U256,
    chainspec::{Chain, build_chain_spec_force_hardfork},
    hardforks::Hardfork,
    types::{
        consensus::BlockHeader,
        reth::primitives::{Block, RecoveredBlock},
    },
};
use types_base::{
    fork_name::ForkName,
    public_inputs::chunk::{BlockContextV2, ChunkInfo},
};

/// `compression_ratios` can be `None` in host mode.
/// But in guest mode, it must be provided.
pub fn execute(witness: ChunkWitness) -> Result<ChunkInfo, String> {
    let chain = Chain::from_id(witness.blocks[0].chain_id);
    let chain_spec = build_chain_spec_force_hardfork(
        chain,
        match witness.fork_name {
            ForkName::EuclidV1 => Hardfork::Euclid,
            ForkName::EuclidV2 => Hardfork::EuclidV2,
            ForkName::Feynman => Hardfork::Feynman,
        },
    );

    let state_commit_mode = witness.state_commit_mode.clone();
    println!("state_commit_mode: {:?}", state_commit_mode);

    let VerifyResult {
        blocks,
        pre_state_root,
        post_state_root,
        withdraw_root,
        ..
    } = verifier::run(
        witness.blocks,
        chain_spec.clone(),
        state_commit_mode,
        Some(witness.compression_ratios.clone()),
    )
    .map_err(|e| format!("verify error: {e}"))?;

    let blocks = manually_drop_on_zkvm!(blocks);
    let mut rlp_buffer = manually_drop_on_zkvm!(Vec::with_capacity(2048));
    let (tx_data_length, tx_data_digest) = blocks.tx_bytes_hash_in(rlp_buffer.as_mut());

    let data_hash = if witness.fork_name < ForkName::EuclidV2 {
        blocks.legacy_data_hash()
    } else {
        B256::ZERO
    };

    let post_msg_queue_hash = if witness.fork_name >= ForkName::EuclidV2 {
        blocks.rolling_msg_queue_hash(witness.prev_msg_queue_hash)
    } else {
        B256::ZERO
    };

    let chunk_info = ChunkInfo {
        chain_id: chain.id(),
        prev_state_root: pre_state_root,
        post_state_root,
        data_hash,
        withdraw_root,
        tx_data_digest,
        tx_data_length: tx_data_length as u64,
        initial_block_number: blocks[0].header().number,
        prev_msg_queue_hash: witness.prev_msg_queue_hash,
        post_msg_queue_hash,
        block_ctxs: blocks.iter().map(block_to_context).collect(),
    };

    println!("chunk_info = {}", chunk_info);

    Ok(chunk_info)
}

fn block_to_context(block: &RecoveredBlock<Block>) -> BlockContextV2 {
    BlockContextV2 {
        timestamp: block.timestamp,
        gas_limit: block.gas_limit,
        base_fee: U256::from(block.base_fee_per_gas().expect("base_fee_expected")),
        num_txs: u16::try_from(block.body().transactions.len()).expect("num txs u16"),
        num_l1_msgs: u16::try_from(
            block
                .body()
                .transactions
                .iter()
                .filter(|tx| tx.is_l1_message())
                .count(),
        )
        .expect("num l1 msgs u16"),
    }
}
                .count(),
        )
        .expect("num l1 msgs u16"),
    }
