use core::iter::Iterator;

use alloy_primitives::B256 as H256;
use itertools::Itertools;
use tiny_keccak::{Hasher, Keccak};
/// Helper struct for the Batch Data.
/// It represent the flattened L2 signed transaction data for each chunk
#[derive(Clone, Debug, Default)]
pub struct BatchData(pub Vec<Vec<u8>>);

/// Helper to generate the required challenge base on the constant of protocol
#[derive(Clone, Debug, Default)]
pub struct BatchDataHash<const N_MAX_CHUNKS: usize> {
    pub chunk_data_digest: Vec<H256>,
    pub meta_data: Vec<u8>,
}

/// From the utility of ether-rs
/// Compute the Keccak-256 hash of input bytes.
///
/// Note that strings are interpreted as UTF-8 bytes,
pub(crate) fn keccak256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut output = [0u8; 32];

    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);

    output
}

impl BatchData {
    /// The number of bytes in payload Data to represent the "payload metadata" section: a u16 to
    /// represent the size of chunks and max_chunks * u32 to represent chunk sizes
    pub fn n_bytes_metadata(max_chunks: usize) -> usize {
        N_BYTES_NUM_CHUNKS + max_chunks * N_BYTES_CHUNK_SIZE
    }

    /// For raw payload data (read from decompressed enveloped data), which is raw batch bytes with metadata, this function segments
    /// the byte stream into chunk segments.
    /// This method is used INSIDE OF zkvm since we can not generate (compress) batch data within
    /// the vm program
    pub fn from_payload(batch_bytes_with_metadata: &[u8], max_chunks: usize) -> Self {
        let n_bytes_metadata = Self::n_bytes_metadata(max_chunks);
        let metadata_bytes = &batch_bytes_with_metadata[..n_bytes_metadata];
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

        // let calculated_len = chunk_lens.sum::<usize>();
        // assert_eq!(
        //     batch_data_len, calculated_len,
        //     "chunk segmentation len must add up to the correct value"
        // );

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

        Self(segmented_batch_data)
    }

    /// Get the blob bytes that encode the batch's metadata.
    ///
    /// metadata_bytes =
    ///     be_bytes(num_valid_chunks) ||
    ///     be_bytes(chunks[0].chunk_size) || ...
    ///     be_bytes(chunks[N_SNARKS-1].chunk_size)
    ///
    /// where:
    /// - chunk_size of a padded chunk is 0
    /// - num_valid_chunks is u16
    /// - each chunk_size is u32
    pub fn metadata_bytes<const N_MAX_CHUNKS: usize>(&self) -> Vec<u8> {
        let mut ret = Vec::from((self.0.len() as u16).to_be_bytes());
        for bytes in self
            .0
            .iter()
            .map(|chunk_byte| chunk_byte.len())
            .chain(std::iter::repeat(0))
            .map(|chunk_size| (chunk_size as u32).to_be_bytes())
            .take(N_MAX_CHUNKS)
        {
            ret.extend_from_slice(&bytes);
        }

        ret
    }
}

/// The number of bytes to encode number of chunks in a batch.
const N_BYTES_NUM_CHUNKS: usize = 2;

/// The number of rows to encode chunk size (u32).
const N_BYTES_CHUNK_SIZE: usize = 4;

impl<const N_MAX_CHUNKS: usize> BatchDataHash<N_MAX_CHUNKS> {
    /// Get the preimage of the challenge digest.
    pub(crate) fn get_challenge_digest_preimage(&self, versioned_hash: H256) -> Vec<u8> {
        // preimage =
        //     metadata_digest ||
        //     chunk[0].chunk_data_digest || ...
        //     chunk[N_SNARKS-1].chunk_data_digest ||
        //     blob_versioned_hash
        //
        // where chunk_data_digest for a padded chunk is set equal to the "last valid chunk"'s
        // chunk_data_digest.
        let mut preimage = Vec::from(keccak256(&self.meta_data));
        let last_digest = self.chunk_data_digest.last().expect("at least we have one");
        for chunk_digest in self
            .chunk_data_digest
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
    pub(crate) fn get_challenge_digest(&self, versioned_hash: H256) -> H256 {
        let challenge_digest = keccak256(self.get_challenge_digest_preimage(versioned_hash));
        H256::from(&challenge_digest)
    }
}

impl<const N_MAX_CHUNKS: usize> From<&BatchData> for BatchDataHash<N_MAX_CHUNKS> {
    fn from(batch_data: &BatchData) -> Self {
        let chunk_data_digest = batch_data
            .0
            .iter()
            .map(|bytes| H256::from(keccak256(bytes)))
            .collect();

        Self {
            meta_data: batch_data.metadata_bytes::<N_MAX_CHUNKS>(),
            chunk_data_digest,
        }
    }
}
