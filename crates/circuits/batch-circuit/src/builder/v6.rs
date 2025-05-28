use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types_batch::{BatchHeader, BatchHeaderV6, EnvelopeV6, PayloadV6};
use scroll_zkvm_circuit_input_types_circuit::public_inputs::{batch::BatchInfo, chunk::ChunkInfo};

use crate::blob_consistency::BlobPolynomial;

/// Builder that consumes DA-codec@v6 [`BatchHeader`][BatchHeaderV6] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct BatchInfoBuilderV6;

impl BatchInfoBuilderV6 {
    /// Build the public-input values [`BatchInfo`] for the [`BatchCircuit`][crate::circuit::BatchCircuit]
    /// by processing the witness, while making some validations.
    pub fn build(
        batch_header: &BatchHeaderV6,
        chunk_infos: &[ChunkInfo],
        blob_bytes: &[u8],
    ) -> BatchInfo {
        // Construct the batch payload using blob bytes.
        let envelope = EnvelopeV6::from(blob_bytes);
        let payload = PayloadV6::from(&envelope);

        // Verify consistency of the EIP-4844 blob.
        //
        // - The challenge (z) MUST match.
        // - The evaluation (y) MUST match.
        let blob_consistency = BlobPolynomial::new(blob_bytes);
        let challenge_digest = payload.get_challenge_digest(batch_header.blob_versioned_hash);
        let blob_data_proof = blob_consistency.evaluate(challenge_digest);
        use openvm_algebra_guest::IntMod;
        assert_eq!(
            B256::new(blob_data_proof.0.to_be_bytes()),
            batch_header.blob_data_proof[0]
        );
        assert_eq!(
            B256::new(blob_data_proof.1.to_be_bytes()),
            batch_header.blob_data_proof[1]
        );

        // Validate payload (batch data).
        let (first, last) = payload.validate(batch_header, chunk_infos);

        BatchInfo {
            parent_state_root: first.prev_state_root,
            parent_batch_hash: batch_header.parent_batch_hash,
            state_root: last.post_state_root,
            batch_hash: batch_header.batch_hash(),
            chain_id: last.chain_id,
            withdraw_root: last.withdraw_root,
            prev_msg_queue_hash: Default::default(),
            post_msg_queue_hash: Default::default(),
        }
    }
}
