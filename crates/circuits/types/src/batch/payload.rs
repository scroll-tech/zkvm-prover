use alloy_primitives::B256;
use itertools::Itertools;
use crate::utils::keccak256;

/// The number of bytes to encode number of chunks in a batch.
const N_BYTES_NUM_CHUNKS: usize = 2;

/// The number of rows to encode chunk size (u32).
const N_BYTES_CHUNK_SIZE: usize = 4;

pub const MAX_AGG_CHUNKS: usize = 45;

pub struct PayloadV3<const N_MAX_CHUNKS: usize> {}

impl<const N_MAX_CHUNKS: usize> PayloadV3<N_MAX_CHUNKS> {

    /// The number of bytes in payload Data to represent the "payload metadata" section: a u16 to
    /// represent the size of chunks and max_chunks * u32 to represent chunk sizes
    const fn n_bytes_metadata() -> usize {
        N_BYTES_NUM_CHUNKS + (N_MAX_CHUNKS * N_BYTES_CHUNK_SIZE)
    }

    /// parsed the payload_data with v3 format and calculate the challenge
    pub fn challenge(
        payload_data: &[u8],
        versioned_hash: B256,
    ) -> B256 {
        let n_bytes_metadata = Self::n_bytes_metadata();
        let metadata_bytes = &payload_data[..n_bytes_metadata];
        let metadata_digest = keccak256(metadata_bytes);
        let batch_bytes = &payload_data[n_bytes_metadata..];

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

        let chunk_data_digests : Vec<B256> = segmented_batch_data
            .iter()
            .map(|bytes| B256::from(keccak256(bytes)))
            .collect();

        // preimage =
        //     metadata_digest ||
        //     chunk[0].chunk_data_digest || ...
        //     chunk[N_SNARKS-1].chunk_data_digest ||
        //     blob_versioned_hash
        //
        // where chunk_data_digest for a padded chunk is set equal to the "last valid chunk"'s
        // chunk_data_digest.
        let mut preimage = metadata_digest.to_vec();
        let last_digest = chunk_data_digests
            .last()
            .expect("at least we have one");
        for chunk_digest in chunk_data_digests
            .iter()
            .chain(std::iter::repeat(last_digest))
            .take(N_MAX_CHUNKS)
        {
            preimage.extend_from_slice(chunk_digest.as_slice());
        }
        preimage.extend_from_slice(versioned_hash.as_slice());            

        keccak256(preimage)

    }

}

pub struct PayloadV7 {}

impl PayloadV7 {
    /// use payload_data and calculate the challenge under v7 protocol
    pub fn challenge_digest(
        payload_data: &[u8],
        versioned_hash: B256,
    ) -> B256 {

        // primage = keccak(blobBytes) + blob_versioned_hash
        let payload_digest = keccak256(payload_data);
        let mut chg_preimage = payload_digest.to_vec();
        chg_preimage.extend(versioned_hash.0);
        keccak256(&chg_preimage)
    }
}