use openvm_native_recursion::hints::Hintable;
use openvm_sdk::StdIn;
use scroll_zkvm_circuit_input_types::batch::{
    BatchHeader, BatchHeaderV3, BatchInfo, BatchWitness, ReferenceHeader,
};

use crate::{
    ChunkProof,
    task::{ProvingTask, flatten_wrapped_proof},
    utils::base64,
};

/// Defines a proving task for batch proof generation.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct BatchProvingTask {
    /// Chunk proofs for the contiguous list of chunks within the batch.
    pub chunk_proofs: Vec<ChunkProof>,
    /// The [`BatchHeaderV3`], as computed on-chain for this batch.
    ///
    /// Ref: https://github.com/scroll-tech/scroll-contracts/blob/2ac4f3f7e090d7127db4b13b3627cb3ce2d762bc/src/libraries/codec/BatchHeaderV3Codec.sol
    pub batch_header: BatchHeaderV3,
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
            reference_header: ReferenceHeader::V3(self.batch_header),
        };

        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&witness)?;
        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);
        for chunk_proof in &self.chunk_proofs {
            let root_input = &chunk_proof.as_proof();
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

        let parent_batch_hash = task.batch_header.parent_batch_hash;
        let batch_hash = task.batch_header.batch_hash();

        Self {
            parent_state_root,
            parent_batch_hash,
            state_root,
            batch_hash,
            chain_id,
            withdraw_root,
        }
    }
}
