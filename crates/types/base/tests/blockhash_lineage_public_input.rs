use alloy_primitives::B256;
use scroll_zkvm_types_base::{
    public_inputs::{
        MultiVersionPublicInputs,
        scroll::{batch::BatchInfo, bundle::BundleInfo, chunk::ChunkInfo},
    },
    version::Version,
};

#[test]
fn scroll_feynman_chunk_pi_commits_to_blockhash() {
    let base = chunk_info(0x10, 0x11, 0x20, 0x21, 0x30, 0x31);
    let mut mutated = base.clone();
    mutated.prev_blockhash = B256::repeat_byte(0xaa);
    mutated.post_blockhash = B256::repeat_byte(0xbb);

    assert_ne!(
        base.pi_by_version(Version::feynman()),
        mutated.pi_by_version(Version::feynman()),
        "Feynman chunk public inputs must commit to prev_blockhash and post_blockhash",
    );
}

#[test]
fn scroll_galileo_v2_chunk_pi_commits_to_blockhash() {
    let base = chunk_info(0x10, 0x11, 0x20, 0x21, 0x30, 0x31);
    let mut mutated = base.clone();
    mutated.prev_blockhash = B256::repeat_byte(0xaa);
    mutated.post_blockhash = B256::repeat_byte(0xbb);

    assert_ne!(
        base.pi_by_version(Version::galileo_v2()),
        mutated.pi_by_version(Version::galileo_v2()),
        "GalileoV2 chunk public inputs must commit to prev_blockhash and post_blockhash",
    );
}

#[test]
fn scroll_euclid_v2_chunk_pi_does_not_commit_to_blockhash() {
    let base = chunk_info(0x10, 0x11, 0x20, 0x21, 0x30, 0x31);
    let mut mutated = base.clone();
    mutated.prev_blockhash = B256::repeat_byte(0xaa);
    mutated.post_blockhash = B256::repeat_byte(0xbb);

    assert_eq!(
        base.pi_by_version(Version::euclid_v2()),
        mutated.pi_by_version(Version::euclid_v2()),
        "EuclidV2 chunk public inputs must remain unchanged (pre-Feynman)",
    );
}

#[test]
fn scroll_feynman_validate_chains_blockhashes_and_numbers() {
    let prev = chunk_info_with_block_range(0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 100, 2);
    let mut next = chunk_info_with_block_range(0x11, 0x12, 0x21, 0x22, 0x31, 0x32, 102, 2);
    next.prev_blockhash = prev.post_blockhash;

    ChunkInfo::validate(&next, &prev, Version::feynman());
}

#[test]
#[should_panic]
fn scroll_feynman_validate_rejects_blockhash_mismatch() {
    let prev = chunk_info_with_block_range(0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 100, 2);
    // prev_blockhash does not match prev.post_blockhash
    let next = chunk_info_with_block_range(0x11, 0x12, 0x21, 0x22, 0xee, 0xef, 102, 2);

    ChunkInfo::validate(&next, &prev, Version::feynman());
}

#[test]
#[should_panic]
fn scroll_feynman_validate_rejects_non_contiguous_block_numbers() {
    let prev = chunk_info_with_block_range(0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 100, 2);
    let mut next = chunk_info_with_block_range(0x11, 0x12, 0x21, 0x22, 0x31, 0x32, 999, 2);
    next.prev_blockhash = prev.post_blockhash;

    ChunkInfo::validate(&next, &prev, Version::feynman());
}

#[test]
fn validium_validate_chains_blockhashes() {
    let prev = chunk_info_with_block_range(0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 100, 1);
    let mut next = chunk_info_with_block_range(0x11, 0x12, 0x21, 0x22, 0x30, 0x32, 101, 1);
    next.prev_blockhash = prev.post_blockhash;

    ChunkInfo::validate(&next, &prev, Version::validium_v1());
}

#[test]
#[should_panic]
fn validium_validate_rejects_blockhash_mismatch() {
    let prev = chunk_info(0x10, 0x11, 0x20, 0x21, 0x30, 0x31);
    let next = chunk_info(0x11, 0x12, 0x21, 0x22, 0xee, 0xef);

    ChunkInfo::validate(&next, &prev, Version::validium_v1());
}

#[test]
fn scroll_feynman_batch_pi_commits_to_blockhash_lineage() {
    let base = batch_info(0x10, 0x11, 0x20, 0x21, 100, 101);
    let mut mutated = base.clone();
    mutated.prev_blockhash = B256::repeat_byte(0xaa);
    mutated.post_blockhash = B256::repeat_byte(0xbb);

    assert_ne!(
        base.pi_by_version(Version::feynman()),
        mutated.pi_by_version(Version::feynman()),
        "Feynman batch public inputs must commit to blockhash lineage",
    );
}

#[test]
fn scroll_euclid_v2_batch_pi_does_not_commit_to_blockhash_lineage() {
    let base = batch_info(0x10, 0x11, 0x20, 0x21, 100, 101);
    let mut mutated = base.clone();
    mutated.prev_blockhash = B256::repeat_byte(0xaa);
    mutated.post_blockhash = B256::repeat_byte(0xbb);

    assert_eq!(
        base.pi_by_version(Version::euclid_v2()),
        mutated.pi_by_version(Version::euclid_v2()),
        "EuclidV2 batch public inputs must remain unchanged",
    );
}

#[test]
fn scroll_feynman_bundle_pi_commits_to_blockhash_lineage() {
    let base = bundle_info(0x10, 0x11, 0x20, 0x21, 100, 101);
    let mut mutated = base.clone();
    mutated.prev_blockhash = B256::repeat_byte(0xaa);
    mutated.post_blockhash = B256::repeat_byte(0xbb);

    assert_ne!(
        base.pi_by_version(Version::feynman()),
        mutated.pi_by_version(Version::feynman()),
        "Feynman bundle public inputs must commit to blockhash lineage",
    );
}

fn chunk_info(
    prev_state: u8,
    post_state: u8,
    prev_msg_queue: u8,
    post_msg_queue: u8,
    prev_blockhash: u8,
    post_blockhash: u8,
) -> ChunkInfo {
    chunk_info_with_block_range(
        prev_state,
        post_state,
        prev_msg_queue,
        post_msg_queue,
        prev_blockhash,
        post_blockhash,
        100,
        1,
    )
}

fn chunk_info_with_block_range(
    prev_state: u8,
    post_state: u8,
    prev_msg_queue: u8,
    post_msg_queue: u8,
    prev_blockhash: u8,
    post_blockhash: u8,
    initial_block_number: u64,
    num_blocks: usize,
) -> ChunkInfo {
    use scroll_zkvm_types_base::public_inputs::scroll::chunk::BlockContextV2;
    use alloy_primitives::U256;

    ChunkInfo {
        chain_id: 534352,
        prev_state_root: B256::repeat_byte(prev_state),
        post_state_root: B256::repeat_byte(post_state),
        withdraw_root: B256::repeat_byte(0x01),
        data_hash: B256::repeat_byte(0x02),
        tx_data_digest: B256::repeat_byte(0x03),
        prev_msg_queue_hash: B256::repeat_byte(prev_msg_queue),
        post_msg_queue_hash: B256::repeat_byte(post_msg_queue),
        tx_data_length: 0,
        initial_block_number,
        block_ctxs: vec![
            BlockContextV2 {
                timestamp: 0,
                base_fee: U256::ZERO,
                gas_limit: 0,
                num_txs: 0,
                num_l1_msgs: 0,
            };
            num_blocks
        ],
        prev_blockhash: B256::repeat_byte(prev_blockhash),
        post_blockhash: B256::repeat_byte(post_blockhash),
        encryption_key: Some(vec![0x42; 32].into_boxed_slice()),
    }
}

fn batch_info(
    prev_state: u8,
    post_state: u8,
    prev_msg_queue: u8,
    post_msg_queue: u8,
    initial_block_number: u64,
    final_block_number: u64,
) -> BatchInfo {
    BatchInfo {
        parent_state_root: B256::repeat_byte(prev_state),
        parent_batch_hash: B256::repeat_byte(0xa0),
        state_root: B256::repeat_byte(post_state),
        batch_hash: B256::repeat_byte(0xb0),
        chain_id: 534352,
        withdraw_root: B256::repeat_byte(0x01),
        prev_msg_queue_hash: B256::repeat_byte(prev_msg_queue),
        post_msg_queue_hash: B256::repeat_byte(post_msg_queue),
        prev_blockhash: B256::repeat_byte(0x30),
        post_blockhash: B256::repeat_byte(0x31),
        initial_block_number,
        final_block_number,
        encryption_key: None,
    }
}

fn bundle_info(
    prev_state: u8,
    post_state: u8,
    initial_block_number: u64,
    final_block_number: u64,
    _unused1: u8,
    _unused2: u8,
) -> BundleInfo {
    BundleInfo {
        chain_id: 534352,
        msg_queue_hash: B256::repeat_byte(0x40),
        num_batches: 1,
        prev_state_root: B256::repeat_byte(prev_state),
        prev_batch_hash: B256::repeat_byte(0xa0),
        post_state_root: B256::repeat_byte(post_state),
        batch_hash: B256::repeat_byte(0xb0),
        withdraw_root: B256::repeat_byte(0x01),
        prev_blockhash: B256::repeat_byte(0x30),
        post_blockhash: B256::repeat_byte(0x31),
        initial_block_number,
        final_block_number,
        encryption_key: None,
    }
}
