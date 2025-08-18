use crate::{ArchivedChunkWitness, ChunkWitnessExt};
use sbv_core::verifier::{self, VerifyResult};
use sbv_helpers::manually_drop_on_zkvm;
use sbv_primitives::{
    BlockWitness, U256,
    chainspec::{Chain, build_chain_spec_force_hardfork},
    hardforks::Hardfork,
};
use std::convert::Infallible;
use types_base::{
    fork_name::ArchivedForkName,
    public_inputs::chunk::{ChunkExt, ChunkInfo},
};

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
    )
    .map_err(|e| format!("verify error: {e}"))?;

    let blocks = manually_drop_on_zkvm!(blocks);
    let mut rlp_buffer = manually_drop_on_zkvm!(Vec::with_capacity(2048));
    let (tx_data_length, tx_data_digest) = blocks.tx_bytes_hash_in(rlp_buffer.as_mut());

    let chunk_info = ChunkInfo {
        chain_id: chain.id(),
        prev_state_root: pre_state_root,
        post_state_root,
        data_hash: witness.legacy_data_hash(&*blocks).unwrap_or_default(),
        withdraw_root,
        tx_data_digest,
        tx_data_length: tx_data_length as u64,
        initial_block_number: blocks[0].header().number,
        prev_msg_queue_hash: witness.prev_msg_queue_hash.into(),
        post_msg_queue_hash: witness.rolling_msg_queue_hash(&*blocks).unwrap_or_default(),
        block_ctxs: blocks.iter().map(Into::into).collect(),
    };

    println!("chunk_info = {:#?}", chunk_info);

    Ok(chunk_info)
}
