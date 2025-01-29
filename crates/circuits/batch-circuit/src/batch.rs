use core::iter::Iterator;

use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types::{
    PublicInputs,
    batch::{BatchHeader, BatchHeaderV3},
    chunk::ChunkInfo,
    utils::keccak256,
};
use vm_zstd::process;

use crate::{blob_consistency::BlobConsistency, payload::Payload};

/// A batch is a set of N_SNARKS num of continuous chunks
/// - the first k chunks are from real traces
/// - the last (#N_SNARKS-k) chunks are from empty traces
#[allow(dead_code)]
pub struct PIBuilder {
    /// the state root of the parent batch
    pub parent_state_root: B256,
    /// the batch header digest of the parent batch.
    pub parent_batch_hash: B256,
    /// The state root of the current batch
    pub state_root: B256,
    /// The batch header digest of the current batch.
    pub batch_hash: B256,
    /// Chain ID of the network.
    pub chain_id: u64,
    /// The withdraw root of the current batch
    pub withdraw_root: B256,
}

impl PublicInputs for PIBuilder {
    fn pi_hash(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(self.parent_state_root.as_slice())
                .chain(self.parent_batch_hash.as_slice())
                .chain(self.state_root.as_slice())
                .chain(self.batch_hash.as_slice())
                .chain(self.chain_id.to_be_bytes().as_slice())
                .chain(self.withdraw_root.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    fn validate(&self, _prev_pi: &Self) {
        unimplemented!("should be required for bundle circuit");
    }
}

struct ChunksSeq<'a>(&'a ChunkInfo, &'a ChunkInfo);

impl<'a> ChunksSeq<'a> {
    pub fn prev_state_root(&self) -> B256 {
        self.0.prev_state_root
    }
    pub fn post_state_root(&self) -> B256 {
        self.1.post_state_root
    }
    pub fn withdraw_root(&self) -> B256 {
        self.1.withdraw_root
    }
    pub fn chain_id(&self) -> u64 {
        self.1.chain_id
    }

    // verify the input chunks
    pub fn new(chunks_info: impl Iterator<Item = &'a ChunkInfo> + Clone) -> Self {
        let first = chunks_info.clone().nth(0);
        let last = chunks_info.reduce(|prev, next| {
            assert_eq!(prev.post_state_root, next.prev_state_root);
            assert_eq!(prev.chain_id, next.chain_id);
            next
        });

        Self(first.expect("at least one"), last.expect("at least one"))
    }
}

impl PIBuilder {
    /// Build PI with batch header encoded with v3
    /// It require some l1 message information obtained from block traces
    pub fn construct_with_header_v3<'a, const N_MAX_CHUNKS: usize>(
        last_header: impl BatchHeader,
        chunks_info: impl Iterator<Item = &'a ChunkInfo> + Clone,
        blob_bytes: &[u8],
        blob_versioned_hash: B256,
        l1_message_popped: u64,
        total_l1_message_popped: u64,
        last_block_timestamp: u64,
    ) -> Self {

        // handling blob data
        // TODO: upgrade for the new enveloped format
        let payload = if blob_bytes[0] & 1 == 1 {
            let enveloped_bytes = process(&blob_bytes[1..]).unwrap().decoded_data;
            // println!(
            //     "{} bytes blob, old enveloped format: compressed payload, decoded to bytes {}",
            //     blob_bytes.len(),
            //     enveloped_bytes.len()
            // );
            Payload::<N_MAX_CHUNKS>::from_payload(&enveloped_bytes)
        } else {
            // println!(
            //     "{} bytes blob, old enveloped format: uncompressed payload",
            //     blob_bytes.len()
            // );
            Payload::<N_MAX_CHUNKS>::from_payload(&blob_bytes[1..])
        };

        // verify the tx data is match with fields in chunk info
        let _ = chunks_info.clone()
        .zip(payload.chunk_data_digests.as_slice())
        .inspect(|(chk_info, &tx_bytes_digest)|{
            assert_eq!(chk_info.tx_data_digest, tx_bytes_digest);
        });

        // TODO: optimize with hasher
        let batch_data_hash_preimage = chunks_info
            .clone()
            .flat_map(|chunk_info| chunk_info.data_hash.0)
            .collect::<Vec<_>>();
        let batch_data_hash = keccak256(batch_data_hash_preimage);

        // println!(
        //     "calculated batch_data_hash {:?}",
        //     B256::from(batch_data_hash)
        // );

        let blob_consistency = BlobConsistency::new(blob_bytes);
        let challenge_digest = payload.get_challenge_digest(blob_versioned_hash);
        let blob_data_proof = blob_consistency.blob_data_proof(challenge_digest);

        let parent_batch_hash = last_header.batch_hash();
        let batch_header = BatchHeaderV3 {
            version: last_header.version(),
            batch_index: last_header.index() + 1,
            l1_message_popped,
            total_l1_message_popped,
            parent_batch_hash,
            last_block_timestamp,
            data_hash: batch_data_hash,
            blob_versioned_hash,
            blob_data_proof,
        };


        let batch_hash = batch_header.batch_hash();
        let chunks_seq = ChunksSeq::new(chunks_info.clone());

        Self {
            parent_state_root: chunks_seq.prev_state_root(),
            parent_batch_hash,
            state_root: chunks_seq.post_state_root(),
            batch_hash,
            chain_id: chunks_seq.chain_id(),
            withdraw_root: chunks_seq.withdraw_root(),
        }
    }
}
