use scroll_zkvm_circuit_input_types::{
    batch::{BatchHeader, BatchHeaderV7, BatchInfo, Bytes48},
    chunk::ChunkInfo,
};

use openvm_ecc_guest::{
    halo2curves::bls12_381::G1Affine as Halo2G1Affine, weierstrass::WeierstrassPoint,
};

use crate::blob_consistency::{
    BlobPolynomial, N_BLOB_BYTES, convert_bls12381_halo2_g1_to_g1, kzg_to_versioned_hash,
    verify_kzg_proof,
};

/// Builder that consumes DA-codec@v7 [`BatchHeader`][BatchHeaderV7] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct BatchInfoBuilderV7;

impl BatchInfoBuilderV7 {
    /// Build the public-input values [`BatchInfo`] for the [`BatchCircuit`][crate::circuit::BatchCircuit]
    /// by processing the witness, while making some validations.
    pub fn build(
        header: &BatchHeaderV7,
        chunks_info: &[ChunkInfo],
        blob_bytes: &[u8],
        kzg_commitment: &Bytes48,
        kzg_proof: &Bytes48,
    ) -> BatchInfo {
        // Sanity check on the length of unpadded blob bytes.
        assert!(
            blob_bytes.len() < N_BLOB_BYTES,
            "blob-envelope bigger than allowed"
        );

        let envelope_bytes = {
            let mut padded = blob_bytes.to_vec();
            padded.resize(N_BLOB_BYTES, 0);
            padded
        };
        let envelope = crate::payload::v7::EnvelopeV7::from(envelope_bytes.as_slice());
        let payload = crate::payload::v7::PayloadV7::from(&envelope);

        // TODO: add validations (payload).

        // Barycentric evaluation of blob polynomial.
        let challenge_digest = envelope.challenge_digest(header.blob_versioned_hash);
        let blob_poly = BlobPolynomial::new(blob_bytes);
        let (challenge, evaluation) = blob_poly.evaluate(challenge_digest);

        // Verify that the KZG commitment does in fact match the on-chain versioned hash.
        assert_eq!(
            kzg_to_versioned_hash(kzg_commitment.as_slice()),
            header.blob_versioned_hash,
            "kzg_to_versioned_hash"
        );

        // Verify KZG proof.
        {
            let commitment = convert_bls12381_halo2_g1_to_g1(
                Halo2G1Affine::from_compressed_be(kzg_commitment).unwrap(),
            );
            let proof = convert_bls12381_halo2_g1_to_g1(
                Halo2G1Affine::from_compressed_be(kzg_proof).unwrap(),
            );
            verify_kzg_proof(
                challenge,
                evaluation,
                (commitment.x().clone(), commitment.y().clone()),
                (proof.x().clone(), proof.y().clone()),
            );
        }

        // Get the first and last chunks' info, to construct the batch info.
        let (first, last) = (
            chunks_info.first().expect("at least one chunk in batch"),
            chunks_info.last().expect("at least one chunk in batch"),
        );

        BatchInfo {
            parent_state_root: first.prev_state_root,
            parent_batch_hash: header.parent_batch_hash,
            state_root: last.post_state_root,
            batch_hash: header.batch_hash(),
            chain_id: last.chain_id,
            withdraw_root: last.withdraw_root,
            prev_msg_queue_hash: first.prev_msg_queue_hash,
            post_msg_queue_hash: last.post_msg_queue_hash,
        }
    }
}
