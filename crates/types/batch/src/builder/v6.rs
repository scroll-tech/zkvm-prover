use alloy_primitives::B256;
use types_base::public_inputs::scroll::batch::BatchInfo;

use crate::{
    BatchHeader, PayloadV6,
    blob_consistency::BlobPolynomial,
    payload::{Envelope, Payload},
};

/// Builder that consumes DA-codec@v6 [`BatchHeader`][BatchHeaderV6] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct BatchInfoBuilderV6;

impl super::BatchInfoBuilder for BatchInfoBuilderV6 {
    type Payload = PayloadV6;

    fn build(
        _version: u8,
        args: super::BuilderArgs<<Self::Payload as crate::payload::Payload>::BatchHeader>,
    ) -> BatchInfo {
        // Construct the batch payload using blob bytes.
        let envelope = <<Self::Payload as Payload>::Envelope as Envelope>::from_slice(
            args.blob_bytes.as_slice(),
        );
        let payload = Self::Payload::from_envelope(&envelope);

        // Verify consistency of the EIP-4844 blob.
        //
        // - The challenge (z) MUST match.
        // - The evaluation (y) MUST match.
        let blob_consistency = BlobPolynomial::new(args.blob_bytes.as_slice());
        let challenge_digest = payload.get_challenge_digest(args.header.blob_versioned_hash);
        let blob_data_proof = blob_consistency.evaluate(challenge_digest);
        use openvm_pairing_guest::algebra::IntMod;
        assert_eq!(
            B256::new(blob_data_proof.0.to_be_bytes()),
            args.header.blob_data_proof[0]
        );
        assert_eq!(
            B256::new(blob_data_proof.1.to_be_bytes()),
            args.header.blob_data_proof[1]
        );

        // Validate payload (batch data).
        let (first, last) = payload.validate(&args.header, args.chunk_infos.as_slice());

        BatchInfo {
            parent_state_root: first.prev_state_root,
            parent_batch_hash: args.header.parent_batch_hash,
            state_root: last.post_state_root,
            batch_hash: args.header.batch_hash(),
            chain_id: last.chain_id,
            withdraw_root: last.withdraw_root,
            prev_msg_queue_hash: Default::default(),
            post_msg_queue_hash: Default::default(),
            encryption_key: Default::default(),
        }
    }
}
