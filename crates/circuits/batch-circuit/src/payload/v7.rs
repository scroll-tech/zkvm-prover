use alloy_primitives::{B256, U256};

use crate::blob_consistency::N_BLOB_BYTES;

/// da-codec@v7
const DA_CODEC_VERSION: u8 = 7;

/// Represents the data contained within an EIP-4844 blob that is published on-chain.
///
/// The bytes following some metadata represent zstd-encoded [`PayloadV7`] if the envelope is
/// indicated as `is_encoded == true`.
#[derive(Debug, Clone)]
pub struct EnvelopeV7 {
    /// The version from da-codec, i.e. v7 in this case.
    pub version: u8,
    /// A single byte boolean flag (value is 0 or 1) to denote whether or not the following blob
    /// bytes represent a batch in its zstd-encoded or raw form.
    pub is_encoded: u8,
    /// The unpadded bytes that possibly encode the [`PayloadV7`].
    pub unpadded_bytes: Vec<u8>,
}

/// Represents the version 2 of block context.
///
/// The difference between v2 and v1 is that the block number field has been removed since v2.
#[derive(Debug, Clone)]
pub struct BlockContextV2 {
    /// The timestamp of the block.
    pub timestamp: u64,
    /// The base fee of the block.
    pub base_fee: U256,
    /// The gas limit of the block.
    pub gas_limit: u64,
    /// The number of transactions in the block, including both L1 msg txs as well as L2 txs.
    pub num_txs: u16,
    /// The number of L1 msg txs in the block.
    pub num_l1_msgs: u16,
}

impl From<&[u8]> for BlockContextV2 {
    fn from(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), SIZE_BLOCK_CTX);

        let timestamp = u64::from_be_bytes(bytes[0..8].try_into().expect("should not fail"));
        let base_fee = U256::from_be_slice(&bytes[8..40]);
        let gas_limit = u64::from_be_bytes(bytes[40..48].try_into().expect("should not fail"));
        let num_txs = u16::from_be_bytes(bytes[48..50].try_into().expect("should not fail"));
        let num_l1_msgs = u16::from_be_bytes(bytes[50..52].try_into().expect("should not fail"));

        Self {
            timestamp,
            base_fee,
            gas_limit,
            num_txs,
            num_l1_msgs,
        }
    }
}

/// Represents the batch data, eventually encoded into an [`EnvelopeV7`].
#[derive(Debug, Clone)]
pub struct PayloadV7 {
    /// The L1 msg queue index of the first L1 msg in the block.
    pub initial_msg_index: u64,
    /// Message queue hash at the end of the previous batch.
    pub prev_msg_queue_hash: B256,
    /// Message queue hash at the end of the current batch.
    pub post_msg_queue_hash: B256,
    /// The block number of the first block in the batch.
    pub initial_block_number: u64,
    /// The number of blocks in the batch.
    pub num_blocks: u16,
    /// The block contexts of each block in the batch.
    pub block_contexts: Vec<BlockContextV2>,
    /// The L2 tx data flattened over every tx in every block in the batch.
    pub tx_data: Vec<u8>,
}

impl From<Vec<u8>> for EnvelopeV7 {
    fn from(blob_bytes: Vec<u8>) -> Self {
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
        }
    }
}

const INDEX_L1_MSG_INDEX: usize = 0;
const INDEX_L1_MSG_QUEUE_HASH: usize = INDEX_L1_MSG_INDEX + 8;
const INDEX_LAST_L1_MSG_QUEUE_HASH: usize = INDEX_L1_MSG_QUEUE_HASH + 32;
const INDEX_L2_BLOCK_NUM: usize = INDEX_LAST_L1_MSG_QUEUE_HASH + 32;
const INDEX_NUM_BLOCKS: usize = INDEX_L2_BLOCK_NUM + 8;
const INDEX_BLOCK_CTX: usize = INDEX_NUM_BLOCKS + 2;
const SIZE_BLOCK_CTX: usize = 52;

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
