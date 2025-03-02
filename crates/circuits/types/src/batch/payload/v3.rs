use core::iter::Iterator;

use alloy_primitives::B256;
use itertools::Itertools;

use crate::{
    batch::BatchHeaderV3,
    chunk::ChunkInfo,
    utils::keccak256,
};

/// The default max chunks for v3 payload
pub const N_MAX_CHUNKS: usize = 45;

/// The number of bytes to encode number of chunks in a batch.
const N_BYTES_NUM_CHUNKS: usize = 2;

/// The number of rows to encode chunk size (u32).
const N_BYTES_CHUNK_SIZE: usize = 4;

impl From<&[u8]> for EnvelopeV3 {
    fn from(blob_bytes: &[u8]) -> Self {
        let is_encoded = blob_bytes[0] & 1 == 1;
        Self {
            is_encoded,
            envelope_bytes: if blob_bytes[0] & 1 == 1 {
                vm_zstd::process(&blob_bytes[1..]).unwrap().decoded_data
            } else {
                Vec::from(&blob_bytes[1..])
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnvelopeV3 {
    /// The original envelope bytes supplied.
    ///
    /// Caching just for re-use later in challenge digest computation.
    pub envelope_bytes: Vec<u8>,
    /// If the enveloped bytes is encoded (compressed) in envelop
    pub is_encoded: bool,
}

impl EnvelopeV3 {
    /// Parse payload bytes and obtain challenge digest
    pub fn challenge_digest(&self, versioned_hash: B256) -> B256 {
        let payload = Payload::from(self);
        payload.get_challenge_digest(versioned_hash)
    }
}

impl From<&EnvelopeV3> for Payload {
    fn from(envelope: &EnvelopeV3) -> Self {
        Self::from_payload(&envelope.envelope_bytes)
    }
}

/// Payload that describes a batch.
#[derive(Clone, Debug, Default)]
pub struct Payload {
    /// Metadata that encodes the sizes of every chunk in the batch.
    pub metadata_digest: B256,
    /// The Keccak digests of transaction bytes for every chunk in the batch.
    ///
    /// The `chunk_data_digest` is a part of the chunk-circuit's public input and hence used to
    /// verify that the transaction bytes included in the chunk-circuit indeed match the
    /// transaction bytes made available in the batch.
    pub chunk_data_digests: Vec<B256>,
}

pub type PayloadV3 = Payload;

impl Payload {
    /// For raw payload data (read from decompressed enveloped data), which is raw batch bytes with metadata, this function segments
    /// the byte stream into chunk segments.
    /// This method is used INSIDE OF zkvm since we can not generate (compress) batch data within
    /// the vm program
    pub fn from_payload(batch_bytes_with_metadata: &[u8]) -> Self {
        let n_bytes_metadata = Self::n_bytes_metadata();
        let metadata_bytes = &batch_bytes_with_metadata[..n_bytes_metadata];
        let metadata_digest = keccak256(metadata_bytes);
        let batch_bytes = &batch_bytes_with_metadata[n_bytes_metadata..];

        // Decoded batch bytes require segmentation based on chunk length
        let valid_chunks = metadata_bytes[..N_BYTES_NUM_CHUNKS]
            .iter()
            .fold(0usize, |acc, &d| acc * 256usize + d as usize);

        let chunk_size_bytes = metadata_bytes[N_BYTES_NUM_CHUNKS..]
            .iter()
            .chunks(N_BYTES_CHUNK_SIZE);
        let chunk_lens = chunk_size_bytes
            .into_iter()
            .map(|chunk_bytes| chunk_bytes.fold(0usize, |acc, &d| acc * 256usize + d as usize))
            .take(valid_chunks);

        // reconstruct segments
        let (segmented_batch_data, final_bytes) = chunk_lens.fold(
            (Vec::new(), batch_bytes),
            |(mut datas, rest_bytes), size| {
                datas.push(Vec::from(&rest_bytes[..size]));
                (datas, &rest_bytes[size..])
            },
        );

        assert!(
            final_bytes.is_empty(),
            "chunk segmentation len must add up to the correct value"
        );

        let chunk_data_digests = segmented_batch_data
            .iter()
            .map(|bytes| B256::from(keccak256(bytes)))
            .collect();

        Self {
            metadata_digest,
            chunk_data_digests,
        }
    }

    /// Get the preimage of the challenge digest.
    #[allow(dead_code)]
    pub(crate) fn get_challenge_digest_preimage(&self, versioned_hash: B256) -> Vec<u8> {
        // preimage =
        //     metadata_digest ||
        //     chunk[0].chunk_data_digest || ...
        //     chunk[N_SNARKS-1].chunk_data_digest ||
        //     blob_versioned_hash
        //
        // where chunk_data_digest for a padded chunk is set equal to the "last valid chunk"'s
        // chunk_data_digest.
        let mut preimage = self.metadata_digest.to_vec();
        let last_digest = self
            .chunk_data_digests
            .last()
            .expect("at least we have one");
        for chunk_digest in self
            .chunk_data_digests
            .iter()
            .chain(std::iter::repeat(last_digest))
            .take(N_MAX_CHUNKS)
        {
            preimage.extend_from_slice(chunk_digest.as_slice());
        }
        preimage.extend_from_slice(versioned_hash.as_slice());
        preimage
    }

    /// Compute the challenge digest from blob bytes. which is the combination of
    /// digest for bytes in each chunk
    pub fn get_challenge_digest(&self, versioned_hash: B256) -> B256 {
        keccak256(self.get_challenge_digest_preimage(versioned_hash))
    }

    /// The number of bytes in payload Data to represent the "payload metadata" section: a u16 to
    /// represent the size of chunks and max_chunks * u32 to represent chunk sizes
    const fn n_bytes_metadata() -> usize {
        N_BYTES_NUM_CHUNKS + (N_MAX_CHUNKS * N_BYTES_CHUNK_SIZE)
    }

    /// Validate the payload contents.
    pub fn validate<'a>(
        &self,
        header: &BatchHeaderV3,
        chunk_infos: &'a [ChunkInfo],
    ) -> (&'a ChunkInfo, &'a ChunkInfo){
        // Get the first and last chunks' info, to construct the batch info.
        let (first_chunk, last_chunk) = (
            chunk_infos.first().expect("at least one chunk in batch"),
            chunk_infos.last().expect("at least one chunk in batch"),
        );

        // TODO: validations

        (first_chunk, last_chunk)
    }
}
