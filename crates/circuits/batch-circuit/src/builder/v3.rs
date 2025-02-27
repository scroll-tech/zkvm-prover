use core::iter::Iterator;

use scroll_zkvm_circuit_input_types::{
    batch::{BatchHeader, BatchHeaderV3, BatchInfo},
    chunk::ChunkInfo,
    utils::keccak256,
};
use vm_zstd::process;

use crate::{blob_consistency::BlobConsistency, payload::v3::Payload};

/// Builder that consumes DA-codec@v3 [`BatchHeader`][BatchHeaderV3] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct BatchInfoBuilderV3;

impl BatchInfoBuilderV3 {
    /// Build the public-input values [`BatchInfo`] for the [`BatchCircuit`][crate::circuit::BatchCircuit]
    /// by processing the witness, while making some validations.
    pub fn build<const N_MAX_CHUNKS: usize>(
        batch_header: &BatchHeaderV3,
        chunks_info: &[ChunkInfo],
        blob_bytes: &[u8],
    ) -> BatchInfo {
        // Construct the batch payload using blob bytes.
        let payload = if blob_bytes[0] & 1 == 1 {
            let enveloped_bytes = process(&blob_bytes[1..]).unwrap().decoded_data;
            Payload::<N_MAX_CHUNKS>::from_payload(&enveloped_bytes)
        } else {
            Payload::<N_MAX_CHUNKS>::from_payload(&blob_bytes[1..])
        };

        // Validate the tx data is match with fields in chunk info
        for (chunk_info, &tx_data_digest) in
            chunks_info.iter().zip(payload.chunk_data_digests.iter())
        {
            assert_eq!(chunk_info.tx_data_digest, tx_data_digest);
        }

        // Validate the l1-msg identifier data_hash for the batch.
        let batch_data_hash_preimage = chunks_info
            .iter()
            .flat_map(|chunk_info| chunk_info.data_hash.0)
            .collect::<Vec<_>>();
        let batch_data_hash = keccak256(batch_data_hash_preimage);
        assert_eq!(batch_data_hash, batch_header.data_hash);

        // Verify consistency of the EIP-4844 blob.
        //
        // - The challenge (z) MUST match.
        // - The evaluation (y) MUST match.
        let blob_consistency = BlobConsistency::new(blob_bytes);
        let challenge_digest = payload.get_challenge_digest(batch_header.blob_versioned_hash);
        let blob_data_proof = blob_consistency.blob_data_proof(challenge_digest);
        assert_eq!(blob_data_proof[0], batch_header.blob_data_proof[0]);
        assert_eq!(blob_data_proof[1], batch_header.blob_data_proof[1]);

        // Get the first and last chunks' info, to construct the batch info.
        let (first, last) = (
            chunks_info.first().expect("at least one chunk in batch"),
            chunks_info.last().expect("at least one chunk in batch"),
        );

        BatchInfo {
            parent_state_root: first.prev_state_root,
            parent_batch_hash: batch_header.parent_batch_hash,
            state_root: last.post_state_root,
            batch_hash: batch_header.batch_hash(),
            chain_id: last.chain_id,
            withdraw_root: last.withdraw_root,
        }
    }
}
