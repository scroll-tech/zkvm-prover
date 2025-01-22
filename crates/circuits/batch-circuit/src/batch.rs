use core::iter::Iterator;

use alloy_primitives::B256 as H256;
use itertools::Itertools;

pub use circuit_input_types::batch::{MAX_AGG_CHUNKS, ArchivedBatchTask, ArchivedBatchHeaderV3, BatchHeaderV3};
use super::{chunk::{public_input_hash, ChunkInfo}, blob_data::{BatchData, BatchDataHash, keccak256}, 
    blob_consistency::BlobConsistency, 
};
use vm_zstd::process;

pub trait BatchHeader {
    fn batch_hash(&self) -> H256;
    fn version(&self) -> u8;
    fn index(&self) -> u64;
}

impl BatchHeader for BatchHeaderV3 {
    fn version(&self) -> u8 { self.version }
    fn index(&self) -> u64 { self.batch_index }

    fn batch_hash(&self) -> H256 {
        // the current batch hash is build as
        // keccak256(
        //     version ||
        //     batch_index ||
        //     l1_message_popped ||
        //     total_l1_message_popped ||
        //     batch_data_hash ||
        //     versioned_hash ||
        //     parent_batch_hash ||
        //     last_block_timestamp ||
        //     z ||
        //     y
        // )
        let batch_hash_preimage = [
            vec![self.version].as_slice(),
            self.batch_index.to_be_bytes().as_ref(),
            self.l1_message_popped.to_be_bytes().as_ref(),
            self.total_l1_message_popped.to_be_bytes().as_ref(),
            self.data_hash.as_slice(),
            self.blob_versioned_hash.as_slice(),
            self.parent_batch_hash.as_slice(),
            self.last_block_timestamp.to_be_bytes().as_ref(),
            self.blob_data_proof[0].as_slice(),
            self.blob_data_proof[1].as_slice(),
        ]
        .concat();
        keccak256(batch_hash_preimage).into()
    }
}

impl BatchHeader for ArchivedBatchHeaderV3 {
    fn version(&self) -> u8 { self.version }
    fn index(&self) -> u64 { self.batch_index.into() }

    fn batch_hash(&self) -> H256 {
        let batch_index : u64 = self.batch_index.into();
        let l1_message_popped : u64 = self.l1_message_popped.into();
        let total_l1_message_popped : u64 = self.total_l1_message_popped.into();
        let data_hash : H256 = self.data_hash.into();
        let blob_versioned_hash : H256 = self.blob_versioned_hash.into();
        let parent_batch_hash : H256 = self.parent_batch_hash.into();
        let last_block_timestamp : u64 = self.last_block_timestamp.into();
        let blob_data_proof : [H256; 2] = self.blob_data_proof.map(|h|h.into());
        let batch_hash_preimage = [
            vec![self.version].as_slice(),
            batch_index.to_be_bytes().as_ref(),
            l1_message_popped.to_be_bytes().as_ref(),
            total_l1_message_popped.to_be_bytes().as_ref(),
            data_hash.as_slice(),
            blob_versioned_hash.as_slice(),
            parent_batch_hash.as_slice(),
            last_block_timestamp.to_be_bytes().as_ref(),
            blob_data_proof[0].as_slice(),
            blob_data_proof[1].as_slice(),
        ]
        .concat();
        keccak256(batch_hash_preimage).into()
    }
}

pub trait KnownLastBatchHash {
    fn parent_batch_hash(&self) -> H256;
}

impl KnownLastBatchHash for BatchHeaderV3 {
    fn parent_batch_hash(&self) -> H256 {
        self.parent_batch_hash
    }
}

impl KnownLastBatchHash for ArchivedBatchHeaderV3 {
    fn parent_batch_hash(&self) -> H256 {
        self.parent_batch_hash.into()
    }
}


/// generic for batch header types which also contain information of its parent
pub struct AsLastBatchHeader<'a, T: KnownLastBatchHash + BatchHeader> (pub &'a T);

impl<'a, T: KnownLastBatchHash + BatchHeader> BatchHeader for AsLastBatchHeader<'a, T> {
    fn batch_hash(&self) -> H256 {
        self.0.parent_batch_hash()
    }
    fn version(&self) -> u8 {
        self.0.version()
    }
    fn index(&self) -> u64 {
        self.0.index() - 1
    }
}

/// A batch is a set of N_SNARKS num of continuous chunks
/// - the first k chunks are from real traces
/// - the last (#N_SNARKS-k) chunks are from empty traces
pub struct PIBuilder {
    /// The PI for aggregated chunks
    pub chunks_pi: Vec<H256>,
    /// The (cached) batch hash for batch PI
    pub batch_hash: H256,
    /// Chain ID of the network.
    pub chain_id: u64,
    /// the state root of the parent batch
    pub parent_state_root: H256,
    /// the state root of the current batch
    pub current_state_root: H256,
    /// the withdraw root of the current batch
    pub current_withdraw_root: H256,
    // /// The batch data hash:
    // /// - keccak256([chunk.hash for chunk in batch])
    // pub(crate) data_hash: H256,
    // /// the current batch hash is calculated as:
    // /// - keccak256( version || batch_index || l1_message_popped || total_l1_message_popped ||
    // ///   batch_data_hash || versioned_hash || parent_batch_hash || last_block_timestamp ||
    // ///   z || y)
    // pub(crate) current_batch_hash: H256,
    // /// The number of chunks that contain meaningful data, i.e. not padded chunks.
    // pub(crate) number_of_valid_chunks: usize,
    // /// The blob bytes (may be encoded batch bytes, or may be raw batch bytes).
    // pub(crate) blob_bytes: Vec<u8>,
}

struct ChunksSeq<'a> (&'a ChunkInfo, &'a ChunkInfo);

impl<'a> ChunksSeq<'a> {
    pub fn prev_state_root(&self) -> H256 { self.0.prev_state_root}
    pub fn post_state_root(&self) -> H256 { self.1.post_state_root}
    pub fn withdraw_root(&self) -> Option<H256> { self.1.withdraw_root}
    pub fn chain_id(&self) -> u64 { self.1.chain_id}

    // verify the input chunks
    pub fn new(chunks_info: impl Iterator<Item = &'a ChunkInfo> + Clone) -> Self {

        let first = chunks_info.clone().nth(0);
        let last = chunks_info
        .reduce(|prev, next|{
            assert_eq!(prev.post_state_root, next.prev_state_root);
            assert_eq!(prev.chain_id, next.chain_id);
            next
        });

        Self(
            first.expect("at least one"),
            last.expect("at least one"),
        )
    }
}

impl PIBuilder {

    fn build_chunks_pi<'a>(
        chunks_info: impl Iterator<Item = &'a ChunkInfo>, 
        tx_bytes_digests: &[H256]
    ) -> Vec<H256> {

        chunks_info
        .zip_eq(tx_bytes_digests)
        .map(|(chunk, tx_bytes_digest)|{
            public_input_hash(&chunk, tx_bytes_digest)
        })
        .collect()

    }

    /// Build PI with batch header encoded with v3
    /// It require some l1 message information obtained from block traces
    pub fn construct_with_header_v3<'a, const N_MAX_CHUNKS: usize> (
        last_header: impl BatchHeader,
        chunks_info: impl Iterator<Item = &'a ChunkInfo> + Clone,
        blob_bytes: &[u8],
        blob_versioned_hash: H256,
        l1_message_popped: u64,
        total_l1_message_popped: u64,
        last_block_timestamp: u64,
    ) -> Self {

        println!("constructing PI with header v3 protocol");

        // handling blob data
        let batch_data = if blob_bytes[0] & 1 == 1 {
            let decoded_bytes = process(&blob_bytes[1..]).unwrap().decoded_data;
            println!("decoded blob bytes {} -> {}", blob_bytes.len(), decoded_bytes.len());
            BatchData::from_blob_data(&decoded_bytes, N_MAX_CHUNKS)
        } else {
            println!("direct use blob bytes {}", blob_bytes.len());
            BatchData::from_blob_data(&blob_bytes[1..], N_MAX_CHUNKS)
        };

        let data_hash_helper = BatchDataHash::<N_MAX_CHUNKS>::from(&batch_data);

        let batch_data_hash_preimage = chunks_info.clone()
            .flat_map(|chunk_info| chunk_info.data_hash.0)
            .collect::<Vec<_>>();
        let batch_data_hash = keccak256(batch_data_hash_preimage);

        println!("calculated batch_data_hash {:?}", H256::from(batch_data_hash));

        let blob_consistency = BlobConsistency::new(blob_bytes);
        let challenge_digest = data_hash_helper.get_challenge_digest(blob_versioned_hash);
        let blob_data_proof = blob_consistency.blob_data_proof(challenge_digest);

        println!("calculated blob proof {:?}", blob_data_proof);

        let batch_header = BatchHeaderV3 {
            version: last_header.version(),
            batch_index: last_header.index() + 1,
            l1_message_popped,
            total_l1_message_popped,
            parent_batch_hash: last_header.batch_hash(),
            last_block_timestamp,
            data_hash: batch_data_hash.into(),
            blob_versioned_hash,
            blob_data_proof,
        };

        // println!("{:#?}", batch_header);

        let batch_hash = batch_header.batch_hash();
        println!("re construct batch header for batch hash {:?}", batch_hash);


        let chunks_seq = ChunksSeq::new(chunks_info.clone());

        Self {
            batch_hash,
            chunks_pi: Self::build_chunks_pi(chunks_info, &data_hash_helper.chunk_data_digest),
            parent_state_root: chunks_seq.prev_state_root(),
            current_state_root: chunks_seq.post_state_root(),
            chain_id: chunks_seq.chain_id(),
            current_withdraw_root: chunks_seq.withdraw_root().unwrap_or_default(),
        }

    }

}
