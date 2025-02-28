use alloy_primitives::U256;
use c_kzg::Bytes48;
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::StdIn;
use scroll_zkvm_circuit_input_types::batch::{
    BatchHeader, BatchInfo, BatchWitness, PointEvalWitness, ReferenceHeader,
};
#[cfg(not(feature = "euclidv2"))]
use scroll_zkvm_circuit_input_types::batch::{
    BatchHeaderV3 as BatchHeaderT, EnvelopeV3 as Envelope,
};
#[cfg(feature = "euclidv2")]
use scroll_zkvm_circuit_input_types::batch::{
    BatchHeaderV7 as BatchHeaderT, EnvelopeV7 as Envelope,
};
use serde::{Deserialize, Serialize};

use crate::{
    ChunkProof,
    task::{ProvingTask, flatten_wrapped_proof},
    utils::{base64, point_eval},
};

/// Defines a proving task for batch proof generation, the format
/// is compatible with both pre-euclidv2 and euclidv2
#[derive(Clone, Deserialize, Serialize)]
pub struct BatchProvingTask {
    /// Chunk proofs for the contiguous list of chunks within the batch.
    pub chunk_proofs: Vec<ChunkProof>,
    /// The [`BatchHeaderV3/V7`], as computed on-chain for this batch.
    pub batch_header: BatchHeaderT,
    /// The bytes encoding the batch data that will finally be published on-chain in the form of an
    /// EIP-4844 blob.
    #[serde(with = "base64")]
    pub blob_bytes: Vec<u8>,
    /// Challenge digest computed using the blob's bytes and versioned hash.
    pub challenge_digest: Option<U256>,
    /// KZG commitment for the blob.
    pub kzg_commitment: Option<Bytes48>,
    /// KZG proof.
    pub kzg_proof: Option<Bytes48>,
}

impl ProvingTask for BatchProvingTask {
    fn identifier(&self) -> String {
        self.batch_header.batch_hash().to_string()
    }

    fn build_guest_input(&self) -> Result<StdIn, rkyv::rancor::Error> {
        // calculate point eval needed and compare with task input
        let (kzg_commitment, kzg_proof, challenge_digest) = {
            let blob = point_eval::to_blob(&self.blob_bytes);
            let commitment = point_eval::blob_to_kzg_commitment(&blob);
            let challenge_digest = Envelope::from(self.blob_bytes.as_slice())
                .challenge_digest(point_eval::get_versioned_hash(&commitment));

            let (proof, _) = point_eval::get_kzg_proof(&blob, challenge_digest);

            (commitment.to_bytes(), proof.to_bytes(), challenge_digest)
        };

        if let Some(k) = &self.kzg_commitment {
            assert_eq!(k, &kzg_commitment);
        }

        if let Some(p) = &self.kzg_proof {
            assert_eq!(p, &kzg_proof);
        }

        if let Some(c) = &self.challenge_digest {
            assert_eq!(*c, U256::from_be_bytes(challenge_digest.0));
        }

        let point_eval_witness = PointEvalWitness {
            kzg_commitment: *kzg_commitment,
            kzg_proof: *kzg_proof,
        };

        #[cfg(not(feature = "euclidv2"))]
        let reference_header = ReferenceHeader::V3(self.batch_header);
        #[cfg(feature = "euclidv2")]
        let reference_header = ReferenceHeader::V7(self.batch_header);

        let witness = BatchWitness {
            chunk_proofs: self
                .chunk_proofs
                .iter()
                .map(flatten_wrapped_proof)
                .collect(),
            chunk_infos: self
                .chunk_proofs
                .iter()
                .map(|p| p.metadata.chunk_info.clone())
                .collect(),
            blob_bytes: self.blob_bytes.clone(),
            reference_header,
            point_eval_witness,
        };

        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&witness)?;
        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);
        for chunk_proof in &self.chunk_proofs {
            let root_input = &chunk_proof.proof;
            let streams = root_input.write();
            for s in &streams {
                stdin.write_field(s);
            }
        }
        Ok(stdin)
    }
}

impl From<&BatchProvingTask> for BatchInfo {
    fn from(task: &BatchProvingTask) -> Self {
        let (parent_state_root, state_root, chain_id, withdraw_root) = (
            task.chunk_proofs
                .first()
                .expect("at least one chunk in batch")
                .metadata
                .chunk_info
                .prev_state_root,
            task.chunk_proofs
                .last()
                .expect("at least one chunk in batch")
                .metadata
                .chunk_info
                .post_state_root,
            task.chunk_proofs
                .last()
                .expect("at least one chunk in batch")
                .metadata
                .chunk_info
                .chain_id,
            task.chunk_proofs
                .last()
                .expect("at least one chunk in batch")
                .metadata
                .chunk_info
                .withdraw_root,
        );
        #[cfg(not(feature = "euclidv2"))]
        // before euclidv2 there is no msg queue and we simply default the value
        let (prev_msg_queue_hash, post_msg_queue_hash) = (Default::default(), Default::default());
        #[cfg(feature = "euclidv2")]
        let (prev_msg_queue_hash, post_msg_queue_hash) = (
            task.chunk_proofs
                .first()
                .expect("at least one chunk in batch")
                .metadata
                .chunk_info
                .prev_msg_queue_hash,
            task.chunk_proofs
                .last()
                .expect("at least one chunk in batch")
                .metadata
                .chunk_info
                .post_msg_queue_hash,
        );

        let parent_batch_hash = task.batch_header.parent_batch_hash;
        let batch_hash = task.batch_header.batch_hash();

        Self {
            parent_state_root,
            parent_batch_hash,
            state_root,
            batch_hash,
            chain_id,
            withdraw_root,
            prev_msg_queue_hash,
            post_msg_queue_hash,
        }
    }
}
