use types_base::aggregation::{AggregationInput, ProofCarryingWitness};
use types_base::public_inputs::dogeos::batch::DogeOsBatchInfo;
use types_base::public_inputs::dogeos::chunk::DogeOsChunkInfoExtras;
use types_base::public_inputs::scroll;

/// Witness to the batch circuit.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DogeOsBatchWitness {
    /// Scroll ChunkWitness
    pub inner: crate::BatchWitness,
    pub extras: DogeOsBatchWitnessExtras,
}

/// Other DogeOs-specific fields can be added here
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DogeOsBatchWitnessExtras {
    pub chunk_info_extras: Vec<DogeOsChunkInfoExtras>,
    pub blobstream: openvm_blobstream::GuestInput,
}

impl ProofCarryingWitness for DogeOsBatchWitness {
    fn get_proofs(&self) -> Vec<AggregationInput> {
        self.inner.chunk_proofs.clone()
    }
}

impl From<&DogeOsBatchWitness> for DogeOsBatchInfo {
    fn from(witness: &DogeOsBatchWitness) -> Self {
        let scroll_batch_info = scroll::batch::BatchInfo::from(&witness.inner);

        // TODO: verify blobstream DA proofs

        DogeOsBatchInfo {
            inner: scroll_batch_info,
        }
    }
}
