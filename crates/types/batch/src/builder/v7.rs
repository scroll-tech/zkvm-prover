use std::marker::PhantomData;

use alloy_primitives::B256;
use types_base::public_inputs::scroll::batch::BatchInfo;
use types_base::version::Version;

use crate::PointEvalWitness;
use crate::witness::build_point;
use crate::{
    BatchHeader, PayloadV7,
    blob_consistency::{
        BlobPolynomial, N_BLOB_BYTES, ToIntrinsic, kzg_to_versioned_hash, verify_kzg_proof,
    },
    payload::{Envelope, Payload},
};

pub type BatchInfoBuilderV7 = GenericBatchInfoBuilderV7<PayloadV7>;

/// Builder that consumes DA-codec@v7 [`BatchHeader`][BatchHeaderV7] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct GenericBatchInfoBuilderV7<P> {
    _payload: PhantomData<P>,
}

/// Verify the `blob_bytes` is consistent with the `blob_versioned_hash` by
/// evaluating the blob polynomial at the challenge derived from `challenge_digest`.
fn verify_blob_versioned_hash(
    blob_bytes: &[u8],
    blob_versioned_hash: B256,
    challenge_digest: B256,
    witness: PointEvalWitness,
) {
    #[cfg(feature = "host")]
    {
        use crate::utils::point_eval;
        let kzg_blob = point_eval::to_blob(blob_bytes);
        let kzg_commitment = point_eval::blob_to_kzg_commitment(&kzg_blob);
        assert_eq!(
            point_eval::get_versioned_hash(&kzg_commitment),
            blob_versioned_hash
        );
    }
    let blob_poly = BlobPolynomial::new(blob_bytes);
    // Barycentric evaluation of blob polynomial.
    let (challenge, evaluation) = blob_poly.evaluate(challenge_digest);

    let commitment = build_point(witness.kzg_commitment_x, witness.kzg_commitment_y)
        .expect("fail to build a bls12-381 G1 point from x,y");
    let proof = build_point(witness.kzg_proof_x, witness.kzg_proof_y)
        .expect("fail to build a bls12-381 G1 point from x,y");

    // Verify KZG proof.
    let proof_ok = verify_kzg_proof(
        challenge,
        evaluation,
        commitment.to_intrinsic(),
        proof.to_intrinsic(),
    );
    assert!(proof_ok, "verify_kzg_proof fail!");

    // Verify that the KZG commitment does in fact match the on-chain versioned hash.
    assert_eq!(
        kzg_to_versioned_hash(&commitment.to_compressed_be()),
        blob_versioned_hash,
        "kzg_to_versioned_hash"
    );
}

impl<P: Payload> super::BatchInfoBuilder for GenericBatchInfoBuilderV7<P> {
    type Payload = P;

    fn build(
        version: u8,
        args: super::BuilderArgs<<Self::Payload as crate::payload::Payload>::BatchHeader>,
    ) -> BatchInfo {
        // Sanity check on the length of unpadded blob bytes.
        assert!(
            args.blob_bytes.len() <= N_BLOB_BYTES,
            "blob-envelope bigger than allowed",
        );

        let envelope_bytes = {
            let mut padded = args.blob_bytes.to_vec();
            padded.resize(N_BLOB_BYTES, 0);
            padded
        };
        let envelope = <<Self::Payload as Payload>::Envelope as Envelope>::from_slice(
            envelope_bytes.as_slice(),
        );
        let payload = Self::Payload::from_envelope(&envelope);

        let blob_versioned_hash = args.header.blob_versioned_hash();
        let challenge_digest = envelope.challenge_digest(blob_versioned_hash);

        verify_blob_versioned_hash(
            &args.blob_bytes,
            blob_versioned_hash,
            challenge_digest,
            args.point_eval_witness.expect("should exist"),
        );

        // Validate payload (batch data).
        let (first_chunk, last_chunk) = payload.validate(&args.header, args.chunk_infos.as_slice());

        // Validate versions from the blob and batch header.
        let version = Version::from(version);
        let stf_version = version.stf_version as u8;
        assert_eq!(
            envelope.version(),
            Some(stf_version),
            "blob codec version mismatch: expected(witness)={:?}, got(blob)={:?}",
            stf_version,
            envelope.version(),
        );
        assert_eq!(
            args.header.version(),
            stf_version,
            "batch header version mismatch: expected(witness)={:?}, got(onchain)={:?}",
            stf_version,
            args.header.version()
        );

        BatchInfo {
            parent_state_root: first_chunk.prev_state_root,
            parent_batch_hash: args.header.parent_batch_hash(),
            state_root: last_chunk.post_state_root,
            batch_hash: args.header.batch_hash(),
            chain_id: last_chunk.chain_id,
            withdraw_root: last_chunk.withdraw_root,
            prev_msg_queue_hash: first_chunk.prev_msg_queue_hash,
            post_msg_queue_hash: last_chunk.post_msg_queue_hash,
            encryption_key: None,
        }
    }
}
