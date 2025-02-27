use alloy_primitives::U256;
use c_kzg::Bytes48;
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::StdIn;
use scroll_zkvm_circuit_input_types::batch::{
    BatchHeader, BatchHeaderV7, BatchInfo, BatchWitness, PointEvalWitness, ReferenceHeader,
};
use serde::{Deserialize, Serialize};

use crate::{
    ChunkProof,
    task::{ProvingTask, flatten_wrapped_proof},
    utils::base64,
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
    /// Challenge digest computed using the blob's bytes and versioned hash.
    pub challenge_digest: U256,
    /// KZG commitment for the blob.
    pub kzg_commitment: Bytes48,
    /// KZG proof.
    pub kzg_proof: Bytes48,
}

impl ProvingTask for BatchProvingTask {
    fn identifier(&self) -> String {
        self.batch_header.batch_hash().to_string()
    }

    fn build_guest_input(&self) -> Result<StdIn, rkyv::rancor::Error> {
        let point_eval_witness = PointEvalWitness {
            kzg_commitment: *self.kzg_commitment,
            kzg_proof: *self.kzg_proof,
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
