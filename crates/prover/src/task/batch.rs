use openvm_native_recursion::hints::Hintable;
use openvm_sdk::StdIn;
use scroll_zkvm_circuit_input_types::batch::{
    BatchHeader, BatchHeaderV7, BatchInfo, BatchWitness, PayloadV7,
    PointEvalWitness, ReferenceHeader,

};
use serde::{Deserialize, Serialize};

use crate::{
    ChunkProof,
    task::{ProvingTask, flatten_wrapped_proof},
    utils::{base64, point_eval},
};

/// Defines a proving task for batch proof generation.
#[derive(Clone, Deserialize, Serialize)]
pub struct BatchProvingTask {
    /// Chunk proofs for the contiguous list of chunks within the batch.
    pub chunk_proofs: Vec<ChunkProof>,
    /// The [`BatchHeaderV7`], as computed on-chain for this batch.
    pub batch_header: BatchHeaderV7,
    /// The bytes encoding the batch data that will finally be published on-chain in the form of an
    /// EIP-4844 blob.
    #[serde(with = "base64")]
    pub blob_bytes: Vec<u8>,
}

impl ProvingTask for BatchProvingTask {
    fn identifier(&self) -> String {
        self.batch_header.batch_hash().to_string()
    }

    fn build_guest_input(&self) -> Result<StdIn, rkyv::rancor::Error> {
        let canonical_blob = point_eval::to_blob_bytes(&self.blob_bytes);
        let kzg_commitment = point_eval::blob_to_kzg_commitment(&canonical_blob);
        let versioned_hash = point_eval::get_versioned_hash(&kzg_commitment);

        let data_chg = PayloadV7::challenge_digest(&self.blob_bytes, versioned_hash);
        let (kzg_proof, _) = point_eval::get_kzg_proof(&canonical_blob, data_chg);

        let point_eval_witness = PointEvalWitness {
            kzg_commitment: *kzg_commitment.to_bytes().as_ref(),
            kzg_proof: *kzg_proof.to_bytes().as_ref(),
        };

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
            reference_header: ReferenceHeader::V7(self.batch_header),
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
        let (
            parent_state_root,
            state_root,
            chain_id,
            withdraw_root,
            prev_msg_queue_hash,
            post_msg_queue_hash,
        ) = (
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
