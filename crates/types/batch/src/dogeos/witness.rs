use bridge_adapters_zk::serde::SerdeWrapper;
use bridge_adapters_zk::{StepInputEnvelope, ZkVerifierExt};
use bridge_core::VerifierContext;
use types_base::aggregation::{AggregationInput, ProofCarryingWitness};
use types_base::public_inputs::dogeos::batch::DogeOsBatchInfo;
use types_base::public_inputs::dogeos::chunk::DogeOsChunkInfoExtras;
use types_base::public_inputs::scroll;
use bridge_steps_da::DaInclusionVerifier;

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
    pub verifier_context: SerdeWrapper<VerifierContext>,
    pub inclusion: SerdeWrapper<StepInputEnvelope<DaInclusionVerifier>>,
    // TODO: to be decided later how to handle celestia consensus
    // pub blobstream: openvm_blobstream::GuestInput,
}

impl ProofCarryingWitness for DogeOsBatchWitness {
    fn get_proofs(&self) -> Vec<AggregationInput> {
        self.inner.chunk_proofs.clone()
    }
}

impl From<&DogeOsBatchWitness> for DogeOsBatchInfo {
    fn from(witness: &DogeOsBatchWitness) -> Self {
        DaInclusionVerifier.verify_envelope(
            &witness.extras.inclusion,
            &witness.extras.verifier_context,
        ).expect("failed to verify inclusion proof");

        // TODO: verifying mapping between extras.chunk_info_extras and inner.chunks

        let scroll_batch_info = scroll::batch::BatchInfo::from(&witness.inner);

        DogeOsBatchInfo {
            inner: scroll_batch_info,
        }
    }
}
