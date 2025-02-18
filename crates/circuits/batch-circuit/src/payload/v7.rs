use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types::{
    batch::BatchHeaderV7,
    chunk::{BlockContextV2, ChunkInfo, SIZE_BLOCK_CTX},
    utils::keccak256,
};

use crate::blob_consistency::N_BLOB_BYTES;

/// da-codec@v7
const DA_CODEC_VERSION: u8 = 7;

/// Represents the data contained within an EIP-4844 blob that is published on-chain.
///
/// The bytes following some metadata represent zstd-encoded [`PayloadV7`] if the envelope is
/// indicated as `is_encoded == true`.
#[derive(Debug, Clone)]
pub struct EnvelopeV7 {
    /// The original envelope bytes supplied.
    ///
    /// Caching just for re-use later in challenge digest computation.
    pub envelope_bytes: Vec<u8>,
    /// The version from da-codec, i.e. v7 in this case.
    pub version: u8,
    /// A single byte boolean flag (value is 0 or 1) to denote whether or not the following blob
    /// bytes represent a batch in its zstd-encoded or raw form.
    pub is_encoded: u8,
    /// The unpadded bytes that possibly encode the [`PayloadV7`].
    pub unpadded_bytes: Vec<u8>,
}

impl From<&[u8]> for EnvelopeV7 {
    fn from(blob_bytes: &[u8]) -> Self {
        // The number of bytes is as expected.
        assert_eq!(blob_bytes.len(), N_BLOB_BYTES);

        // The version of the blob encoding was as expected, i.e. da-codec@v7.
        let version = blob_bytes[0];
        assert_eq!(version, DA_CODEC_VERSION);

        // Calculate the unpadded size of the encoded payload.
        //
        // It should be at most the maximum number of bytes allowed.
        let unpadded_size = (blob_bytes[1] as usize) * 256 * 256
            + (blob_bytes[2] as usize) * 256
            + blob_bytes[3] as usize;
        assert!(unpadded_size <= N_BLOB_BYTES - 5);

        // Whether the envelope represents encoded payload or raw payload.
        //
        // Is a boolean.
        let is_encoded = blob_bytes[4];
        assert!(is_encoded <= 1);

        // The padded bytes are all 0s.
        for &padded_byte in blob_bytes.iter().skip(5 + unpadded_size) {
            assert_eq!(padded_byte, 0);
        }

        Self {
            version,
            is_encoded,
            unpadded_bytes: blob_bytes[5..(5 + unpadded_size)].to_vec(),
            envelope_bytes: blob_bytes.to_vec(),
        }
    }
}

impl EnvelopeV7 {
    /// The verification of the EIP-4844 blob is done via point-evaluation precompile
    /// implemented in-circuit.
    ///
    /// We require a random challenge point for this, and using Fiat-Shamir we compute it with
    /// every byte in the blob along with the blob's versioned hash, i.e. an identifier for its KZG
    /// commitment.
    ///
    /// keccak256(
    ///     keccak256(envelope) ||
    ///     versioned hash
    /// )
    pub fn challenge_digest(&self, versioned_hash: B256) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(keccak256(&self.envelope_bytes))
                .chain(versioned_hash.0)
                .collect::<Vec<u8>>(),
        )
    }
}

/// Represents the batch data, eventually encoded into an [`EnvelopeV7`].
#[derive(Debug, Clone)]
pub struct PayloadV7 {
    /// The version from da-codec, i.e. v7 in this case.
    ///
    /// Copied from the envelope.
    pub version: u8,
    /// The L1 msg queue index of the first L1 msg in the block.
    #[allow(dead_code)]
    pub initial_msg_index: u64,
    /// Message queue hash at the end of the previous batch.
    pub prev_msg_queue_hash: B256,
    /// Message queue hash at the end of the current batch.
    pub post_msg_queue_hash: B256,
    /// The block number of the first block in the batch.
    #[allow(dead_code)]
    pub initial_block_number: u64,
    /// The number of blocks in the batch.
    pub num_blocks: u16,
    /// The block contexts of each block in the batch.
    pub block_contexts: Vec<BlockContextV2>,
    /// The L2 tx data flattened over every tx in every block in the batch.
    pub tx_data: Vec<u8>,
}

const INDEX_L1_MSG_INDEX: usize = 0;
const INDEX_L1_MSG_QUEUE_HASH: usize = INDEX_L1_MSG_INDEX + 8;
const INDEX_LAST_L1_MSG_QUEUE_HASH: usize = INDEX_L1_MSG_QUEUE_HASH + 32;
const INDEX_L2_BLOCK_NUM: usize = INDEX_LAST_L1_MSG_QUEUE_HASH + 32;
const INDEX_NUM_BLOCKS: usize = INDEX_L2_BLOCK_NUM + 8;
const INDEX_BLOCK_CTX: usize = INDEX_NUM_BLOCKS + 2;

impl From<&EnvelopeV7> for PayloadV7 {
    fn from(envelope: &EnvelopeV7) -> Self {
        // Conditionally decode depending on the flag set in the envelope.
        let payload_bytes = if envelope.is_encoded & 1 == 1 {
            vm_zstd::process(&envelope.unpadded_bytes)
                .expect("zstd decode should succeed")
                .decoded_data
        } else {
            envelope.unpadded_bytes.to_vec()
        };

        // Sanity check on the payload size.
        assert!(payload_bytes.len() >= INDEX_BLOCK_CTX);
        let num_blocks = u16::from_be_bytes(
            payload_bytes[INDEX_NUM_BLOCKS..INDEX_BLOCK_CTX]
                .try_into()
                .expect("should not fail"),
        );
        assert!(payload_bytes.len() >= INDEX_BLOCK_CTX + ((num_blocks as usize) * SIZE_BLOCK_CTX));

        // Deserialize the other fields.
        let initial_msg_index = u64::from_be_bytes(
            payload_bytes[INDEX_L1_MSG_INDEX..INDEX_L1_MSG_QUEUE_HASH]
                .try_into()
                .expect("should not fail"),
        );
        let prev_msg_queue_hash =
            B256::from_slice(&payload_bytes[INDEX_L1_MSG_QUEUE_HASH..INDEX_LAST_L1_MSG_QUEUE_HASH]);
        let post_msg_queue_hash =
            B256::from_slice(&payload_bytes[INDEX_LAST_L1_MSG_QUEUE_HASH..INDEX_L2_BLOCK_NUM]);
        let initial_block_number = u64::from_be_bytes(
            payload_bytes[INDEX_L2_BLOCK_NUM..INDEX_NUM_BLOCKS]
                .try_into()
                .expect("should not fail"),
        );

        // Deserialize block contexts depending on the number of blocks in the batch.
        let mut block_contexts = Vec::with_capacity(num_blocks as usize);
        for i in 0..num_blocks {
            let start = (i as usize) * SIZE_BLOCK_CTX + INDEX_NUM_BLOCKS;
            block_contexts.push(BlockContextV2::from(
                &payload_bytes[start..(start + SIZE_BLOCK_CTX)],
            ));
        }

        // All remaining bytes are flattened L2 txs.
        let tx_data =
            payload_bytes[INDEX_BLOCK_CTX + ((num_blocks as usize) * SIZE_BLOCK_CTX)..].to_vec();

        Self {
            version: envelope.version,
            initial_msg_index,
            prev_msg_queue_hash,
            post_msg_queue_hash,
            initial_block_number,
            num_blocks,
            block_contexts,
            tx_data,
        }
    }
}

impl PayloadV7 {
    /// Validate the payload contents.
    pub fn validate<'a>(
        &self,
        header: &BatchHeaderV7,
        chunk_infos: &'a [ChunkInfo],
    ) -> (&'a ChunkInfo, &'a ChunkInfo) {
        // Get the first and last chunks' info, to construct the batch info.
        let (first, last) = (
            chunk_infos.first().expect("at least one chunk in batch"),
            chunk_infos.last().expect("at least one chunk in batch"),
        );

        // version from payload is what's present in the on-chain batch header
        assert_eq!(self.version, header.version);

        // number of blocks in the batch
        assert_eq!(
            usize::from(self.num_blocks),
            chunk_infos
                .iter()
                .flat_map(|chunk_info| &chunk_info.block_ctxs)
                .count()
        );
        assert_eq!(usize::from(self.num_blocks), self.block_contexts.len());

        // prev message queue hash
        assert_eq!(self.prev_msg_queue_hash, first.prev_msg_queue_hash);

        // post message queue hash
        assert_eq!(self.post_msg_queue_hash, last.post_msg_queue_hash);

        // for each chunk, the tx_data_digest, i.e. keccak digest of the rlp-encoded L2 tx bytes
        // flattened over every tx in the chunk, should be re-computed and matched against the
        // public input of the chunk-circuit.
        //
        // first check that the total size of rlp-encoded tx data flattened over all txs in the
        // chunk is in fact the size available from the payload.
        assert_eq!(
            u64::try_from(self.tx_data.len()).expect("len(tx-data) is u64"),
            chunk_infos
                .iter()
                .map(|chunk_info| chunk_info.tx_data_length)
                .sum::<u64>(),
        );
        let mut index: usize = 0;
        for chunk_info in chunk_infos.iter() {
            let chunk_size = chunk_info.tx_data_length as usize;
            let chunk_tx_data_digest =
                keccak256(&self.tx_data.as_slice()[index..(index + chunk_size)]);
            assert_eq!(chunk_tx_data_digest, chunk_info.tx_data_digest);
            index += chunk_size;
        }

        // for each block in the batch, check that the block context matches what's provided as
        // witness.
        for (block_ctx, witness_block_ctx) in self.block_contexts.iter().zip(
            chunk_infos
                .iter()
                .flat_map(|chunk_info| &chunk_info.block_ctxs),
        ) {
            assert_eq!(block_ctx.timestamp, witness_block_ctx.timestamp);
            assert_eq!(block_ctx.gas_limit, witness_block_ctx.gas_limit);
            assert_eq!(block_ctx.base_fee, witness_block_ctx.base_fee);
            assert_eq!(block_ctx.num_txs, witness_block_ctx.num_txs);
            assert_eq!(block_ctx.num_l1_msgs, witness_block_ctx.num_l1_msgs);
        }

        (first, last)
    }
}
