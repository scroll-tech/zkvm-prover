use crate::{BatchHeader, BatchHeaderV7, Bytes48, EnvelopeV7, PayloadV7};
use halo2curves_axiom::bls12_381::G1Affine as Bls12_381_G1;
use types_base::public_inputs::{batch::BatchInfo, chunk::ArchivedChunkInfo};

use crate::blob_consistency::{
    BlobPolynomial, EccToPairing, N_BLOB_BYTES, kzg_to_versioned_hash, verify_kzg_proof,
};

/// Builder that consumes DA-codec@v7 [`BatchHeader`][BatchHeaderV7] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct BatchInfoBuilderV7;

impl BatchInfoBuilderV7 {
    /// Build the public-input values [`BatchInfo`] for the [`BatchCircuit`][crate::circuit::BatchCircuit]
    /// by processing the witness, while making some validations.
    pub fn build(
        header: &BatchHeaderV7,
        chunk_infos: &[ArchivedChunkInfo],
        blob_bytes: &[u8],
        kzg_commitment: &Bytes48,
        kzg_proof: &Bytes48,
    ) -> BatchInfo {
        // Sanity check on the length of unpadded blob bytes.
        assert!(
            blob_bytes.len() <= N_BLOB_BYTES,
            "blob-envelope bigger than allowed",
        );

        let envelope_bytes = {
            let mut padded = blob_bytes.to_vec();
            padded.resize(N_BLOB_BYTES, 0);
            padded
        };
        let envelope = EnvelopeV7::from(envelope_bytes.as_slice());
        let payload = PayloadV7::from(&envelope);

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
        let proof_ok = {
            let commitment = Bls12_381_G1::from_compressed_be(kzg_commitment)
                .expect("kzg commitment")
                .convert();
            let proof = Bls12_381_G1::from_compressed_be(kzg_proof)
                .expect("kzg proof")
                .convert();
            verify_kzg_proof(challenge, evaluation, commitment, proof)
        };
        assert!(proof_ok, "pairing fail!");

        // Validate payload (batch data).
        let (first_chunk, last_chunk) = payload.validate(header, chunk_infos);

        BatchInfo {
            parent_state_root: first_chunk.prev_state_root.into(),
            parent_batch_hash: header.parent_batch_hash,
            state_root: last_chunk.post_state_root.into(),
            batch_hash: header.batch_hash(),
            chain_id: last_chunk.chain_id.to_native(),
            withdraw_root: last_chunk.withdraw_root.into(),
            prev_msg_queue_hash: first_chunk.prev_msg_queue_hash.into(),
            post_msg_queue_hash: last_chunk.post_msg_queue_hash.into(),
        }
    }
}
