use alloy_primitives::{B256, keccak256};
use types_base::{
    public_inputs::chunk::{BlockContextV2, ChunkInfo, SIZE_BLOCK_CTX},
    version::VALIDIUM_V1,
};

use crate::{BatchHeader, header::validium::BatchHeaderValidium};

use super::v7::{
    INDEX_BLOCK_CTX, INDEX_L2_BLOCK_NUM, INDEX_NUM_BLOCKS, INDEX_POST_MSG_QUEUE_HASH,
    INDEX_PREV_MSG_QUEUE_HASH,
};

pub struct ValidiumEnvelope<const VERSION: u8> {
    /// The original envelope bytes supplied.
    ///
    /// Caching just for re-use later in challenge digest computation.
    #[allow(dead_code)]
    pub envelope_bytes: Vec<u8>,
    /// The [`Version`][version] byte as per new versioning system.
    ///
    /// [version]: types_base::version::Version
    pub version: u8,
    /// A single byte boolean flag (value is 0 or 1) to denote whether or not the following
    /// bytes represent a batch in its zstd-encoded or raw form.
    pub is_encoded: u8,
    /// The unpadded bytes that can be decoded to the [`ValidiumPayload`].
    pub unpadded_bytes: Vec<u8>,
}

pub struct ValidiumPayload<const VERSION: u8> {
    /// The [`Version`][version] byte as per new versioning system.
    ///
    /// [version]: types_base::version::Version
    pub version: u8,
    /// Message queue hash at the end of the previous validium batch.
    pub prev_msg_queue_hash: B256,
    /// Message queue hash at the end of the current validium batch.
    pub post_msg_queue_hash: B256,
    /// The block number of the first block in the validium batch.
    pub initial_block_number: u64,
    /// The number of blocks in the validium batch.
    pub num_blocks: u16,
    /// The block contexts of each block in the validium batch.
    pub block_contexts: Vec<BlockContextV2>,
    /// The L3 tx data flattened over every tx in every block in the batch.
    pub tx_data: Vec<u8>,
}

impl<const VERSION: u8> ValidiumEnvelope<VERSION> {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        // Check the version of the batch.
        let version = bytes[0];
        assert_eq!(version, VERSION);

        // Calculate the unpadded size of the encoded payload.
        let unpadded_size =
            (bytes[1] as usize) * 256 * 256 + (bytes[2] as usize) * 256 + bytes[3] as usize;

        // Whether the envelope represents encoded payload or raw payload.
        //
        // Is a boolean.
        let is_encoded = bytes[4];
        assert!(is_encoded <= 1);

        // The padded bytes are all 0s.
        for &padded_byte in bytes.iter().skip(5 + unpadded_size) {
            assert_eq!(padded_byte, 0);
        }

        Self {
            version,
            is_encoded,
            unpadded_bytes: bytes[5..(5 + unpadded_size)].to_vec(),
            envelope_bytes: bytes.to_vec(),
        }
    }
}

impl<const VERSION: u8> ValidiumPayload<VERSION> {
    pub fn from_envelope(envelope: &ValidiumEnvelope<VERSION>) -> Self {
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
        let prev_msg_queue_hash =
            B256::from_slice(&payload_bytes[INDEX_PREV_MSG_QUEUE_HASH..INDEX_POST_MSG_QUEUE_HASH]);
        let post_msg_queue_hash =
            B256::from_slice(&payload_bytes[INDEX_POST_MSG_QUEUE_HASH..INDEX_L2_BLOCK_NUM]);
        let initial_block_number = u64::from_be_bytes(
            payload_bytes[INDEX_L2_BLOCK_NUM..INDEX_NUM_BLOCKS]
                .try_into()
                .expect("should not fail"),
        );

        // Deserialize block contexts depending on the number of blocks in the batch.
        let mut block_contexts = Vec::with_capacity(num_blocks as usize);
        for i in 0..num_blocks {
            let start = (i as usize) * SIZE_BLOCK_CTX + INDEX_BLOCK_CTX;
            block_contexts.push(BlockContextV2::from(
                &payload_bytes[start..(start + SIZE_BLOCK_CTX)],
            ));
        }

        // All remaining bytes are flattened L2 txs.
        let tx_data =
            payload_bytes[INDEX_BLOCK_CTX + ((num_blocks as usize) * SIZE_BLOCK_CTX)..].to_vec();

        Self {
            version: envelope.version,
            prev_msg_queue_hash,
            post_msg_queue_hash,
            initial_block_number,
            num_blocks,
            block_contexts,
            tx_data,
        }
    }

    pub fn validate<'a>(
        &self,
        header: &BatchHeaderValidium,
        chunk_infos: &'a [ChunkInfo],
    ) -> (&'a ChunkInfo, &'a ChunkInfo) {
        // Get the first and last chunks' info, to construct the batch info.
        let (first_chunk, last_chunk) = (
            chunk_infos.first().expect("at least one chunk in batch"),
            chunk_infos.last().expect("at least one chunk in batch"),
        );

        // version from payload is what's present in the on-chain batch header
        assert_eq!(self.version, header.version());

        // number of blocks in the batch
        assert_eq!(
            usize::from(self.num_blocks),
            chunk_infos
                .iter()
                .flat_map(|chunk_info| chunk_info.block_ctxs.as_slice())
                .count()
        );
        assert_eq!(usize::from(self.num_blocks), self.block_contexts.len());

        // the block number of the first block in the batch
        assert_eq!(self.initial_block_number, first_chunk.initial_block_number);

        // prev message queue hash
        assert_eq!(
            self.prev_msg_queue_hash.0,
            first_chunk.prev_msg_queue_hash.0
        );

        // post message queue hash
        assert_eq!(self.post_msg_queue_hash.0, last_chunk.post_msg_queue_hash.0);

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
            assert_eq!(chunk_tx_data_digest.0, chunk_info.tx_data_digest.0);
            index += chunk_size;
        }

        // for each block in the batch, check that the block context matches what's provided as
        // witness.
        for (block_ctx, witness_block_ctx) in self.block_contexts.iter().zip(
            chunk_infos
                .iter()
                .flat_map(|chunk_info| chunk_info.block_ctxs.as_slice()),
        ) {
            assert_eq!(block_ctx, witness_block_ctx);
        }

        (first_chunk, last_chunk)
    }
}

pub type ValidiumEnvelopeV1 = ValidiumEnvelope<{ VALIDIUM_V1 }>;

pub type ValidiumPayloadV1 = ValidiumPayload<{ VALIDIUM_V1 }>;
