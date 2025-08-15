use crate::ArchivedChunkWitness;
use sbv_core::verifier::{self, VerifyResult};
use sbv_helpers::manually_drop_on_zkvm;
use sbv_primitives::chainspec::build_chain_spec_force_hardfork;
use sbv_primitives::hardforks::Hardfork;
use sbv_primitives::{
    BlockWitness,
    chainspec::Chain,
    B256, U256
};
use std::convert::Infallible;
use tiny_keccak::{Hasher, Keccak};
use types_base::{fork_name::{ArchivedForkName}, public_inputs::chunk::ChunkInfo};
use types_base::public_inputs::chunk::{BlockChunkExt, TxBytesHashExt};

/// `compression_ratios` can be `None` in host mode.
/// But in guest mode, it must be provided.
pub fn execute(witness: &ArchivedChunkWitness) -> Result<ChunkInfo, String> {
    let chain = Chain::from_id(witness.blocks[0].chain_id());
    let chain_spec = build_chain_spec_force_hardfork(
        chain,
        match witness.fork_name {
            ArchivedForkName::EuclidV1 => Hardfork::Euclid,
            ArchivedForkName::EuclidV2 => Hardfork::EuclidV2,
            ArchivedForkName::Feynman => Hardfork::Feynman,
        },
    );

    let state_commit_mode = rkyv::deserialize::<_, Infallible>(&witness.state_commit_mode).unwrap();
    println!("state_commit_mode: {:?}", state_commit_mode);

    let VerifyResult {
        blocks,
        pre_state_root,
        post_state_root,
        withdraw_root,
        ..
    } = verifier::run(
        witness.blocks.as_slice(),
        chain_spec.clone(),
        state_commit_mode,
        Some(
            witness
                .compression_ratios
                .iter()
                .map(|x| x.iter().map(Into::<U256>::into)),
        ),
    ).map_err(|e| format!("verify error: {e}"))?;

    let blocks = manually_drop_on_zkvm!(blocks);
    let mut rlp_buffer = manually_drop_on_zkvm!(Vec::with_capacity(2048));
    let (tx_data_length, tx_data_digest) = blocks
        .iter()
        .flat_map(|b| b.body().transactions.iter())
        .tx_bytes_hash_in(rlp_buffer.as_mut());

    let data_hash = if witness.fork_name < ArchivedForkName::EuclidV2 {
        let mut data_hasher = Keccak::v256();
        for block in blocks.iter() {
            block.legacy_hash_da_header(&mut data_hasher);
        }
        for block in blocks.iter() {
            block.legacy_hash_l1_msg(&mut data_hasher);
        }
        let mut data_hash = B256::ZERO;
        data_hasher.finalize(&mut data_hash.0);
        data_hash
    } else {
        B256::ZERO
    };

    let post_msg_queue_hash = if witness.fork_name >= ArchivedForkName::EuclidV2 {
        let mut rolling_hash: B256 = witness.prev_msg_queue_hash.into();
        for block in blocks.iter() {
            rolling_hash = block.hash_msg_queue(&rolling_hash);
        }
        rolling_hash
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
        tx_data_length: u64::try_from(tx_data_length).expect("tx_data_length: u64"),
        initial_block_number: blocks[0].header().number,
        prev_msg_queue_hash: witness.prev_msg_queue_hash.into(),
        post_msg_queue_hash,
        block_ctxs: blocks.iter().map(Into::into).collect(),
    };

    println!("chunk_info = {:#?}", chunk_info);

    Ok(chunk_info)
}
