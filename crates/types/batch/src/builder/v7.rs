use std::marker::PhantomData;

use types_base::public_inputs::batch::BatchInfo;

use crate::{
    BatchHeader, PayloadV7,
    blob_consistency::{BlobPolynomial, N_BLOB_BYTES, kzg_to_versioned_hash, verify_kzg_proof},
    payload::{Envelope, Payload},
    witness::decode_point,
};

pub type BatchInfoBuilderV7 = GenericBatchInfoBuilderV7<PayloadV7>;

/// Builder that consumes DA-codec@v7 [`BatchHeader`][BatchHeaderV7] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct GenericBatchInfoBuilderV7<P> {
    _payload: PhantomData<P>,
}

impl<P: Payload> super::BatchInfoBuilder for GenericBatchInfoBuilderV7<P> {
    type Payload = P;

    fn build(
        args: super::BuilderArgs<<Self::Payload as crate::payload::Payload>::BatchHeader>,
    ) -> BatchInfo {
        // Sanity check on the length of unpadded blob bytes.
        assert!(
            args.blob_bytes.len() <= N_BLOB_BYTES,
            "blob-envelope bigger than allowed",
        );

        println!("6002");
        let envelope_bytes = {
            let mut padded = args.blob_bytes.to_vec();
            padded.resize(N_BLOB_BYTES, 0);
            padded
        };
        let envelope = <<Self::Payload as Payload>::Envelope as Envelope>::from_slice(
            envelope_bytes.as_slice(),
        );

        println!("6003");
        let payload = Self::Payload::from_envelope(&envelope);

        println!("6004");
        // Barycentric evaluation of blob polynomial.
        let blob_versioned_hash = args.header.blob_versioned_hash();

        println!("60040");
        let challenge_digest = envelope.challenge_digest(blob_versioned_hash);

        println!("6005");
        let blob_poly = BlobPolynomial::new(args.blob_bytes.as_slice());

        println!("6006");
        let (challenge, evaluation) = blob_poly.evaluate(challenge_digest);

        println!("6007");
        // Verify that the KZG commitment does in fact match the on-chain versioned hash.
        let kzg_commitment = args
            .kzg_commitment
            .expect("batch v7 onwards must have kzg commitment");
        let kzg_proof = args
            .kzg_proof
            .expect("batch v7 onwards must have kzg proof");
        assert_eq!(
            kzg_to_versioned_hash(&kzg_commitment),
            args.header.blob_versioned_hash(),
            "kzg_to_versioned_hash"
        );

        println!("6008");
        // Verify KZG proof.
        let proof_ok = {
            let commitment = decode_point(
                kzg_commitment,
                Some((
                    args.kzg_commitment_hint_x.unwrap(),
                    args.kzg_commitment_hint_y.unwrap(),
                )),
            );
            let proof = decode_point(
                kzg_proof,
                Some((
                    args.kzg_proof_hint_x.unwrap(),
                    args.kzg_proof_hint_y.unwrap(),
                )),
            );

            verify_kzg_proof(challenge, evaluation, commitment, proof)
        };

        println!("6009");
        assert!(proof_ok, "pairing fail!");

        // Validate payload (batch data).
        let (first_chunk, last_chunk) = payload.validate(&args.header, args.chunk_infos.as_slice());

        println!("6010");
        BatchInfo {
            parent_state_root: first_chunk.prev_state_root,
            parent_batch_hash: args.header.parent_batch_hash(),
            state_root: last_chunk.post_state_root,
            batch_hash: args.header.batch_hash(),
            chain_id: last_chunk.chain_id,
            withdraw_root: last_chunk.withdraw_root,
            prev_msg_queue_hash: first_chunk.prev_msg_queue_hash,
            post_msg_queue_hash: last_chunk.post_msg_queue_hash,
        }
    }
}
