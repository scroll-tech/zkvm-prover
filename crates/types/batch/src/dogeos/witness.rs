use bridge_adapters_zk::serde::SerdeWrapper;
use bridge_adapters_zk::{StepInputEnvelope, ZkVerifierExt};
use bridge_core::VerifierContext;
use bridge_steps_da::DaInclusionVerifier;
use types_base::aggregation::{AggregationInput, ProofCarryingWitness};
use types_base::public_inputs::dogeos::batch::{DogeOsBatchInfo, DogeOsBatchInfoExtras};
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
        let scroll_batch_info = scroll::batch::BatchInfo::from(&witness.inner);
        verify_da_inclusion(witness, &scroll_batch_info);

        DogeOsBatchInfo {
            inner: scroll_batch_info,
            extras: DogeOsBatchInfoExtras {}
        }
    }
}

fn verify_da_inclusion(witness: &DogeOsBatchWitness, _scroll_batch_info: &scroll::batch::BatchInfo) {
    DaInclusionVerifier
        .verify_envelope(&witness.extras.inclusion, &witness.extras.verifier_context)
        .expect("failed to verify inclusion proof");

    // TODO: uncomment and complete these checks
    // let da_header = &witness.extras.inclusion.artifact.v2_header;
    //
    // // See: https://github.com/DogeOS69/dogeos-core/tree/feat/trust-minimized-bridge-crates/crates/common_types/src/protos
    // // | Field | Type / Size | Meaning | Source / Notes |
    // // |-------|-------------|---------|----------------|
    // // | `prev_state_root` | bytes (32) | L2 state root before batch | DogeOS RPC |
    // assert_eq!(
    //     da_header.prev_state_root,
    //     scroll_batch_info.parent_state_root
    // );
    // // | `state_root` | bytes (32) | L2 state root after batch | DogeOS RPC |
    // assert_eq!(da_header.state_root, scroll_batch_info.state_root);
    // // | `prev_batch_hash` | bytes (32) | Hash of previous batch | From `commitBatches` inputs |
    // assert_eq!(
    //     da_header.prev_batch_hash,
    //     scroll_batch_info.parent_batch_hash
    // );
    // // | `batch_hash` | bytes (32) | Hash of current batch | `calculate_batch_hash` (codec version, batch index, blob commitment, prev batch hash) |
    // assert_eq!(da_header.batch_hash, scroll_batch_info.batch_hash);
    // // | `prev_l1_message_queue_hash` | bytes (32) | Pre-batch queue hash | Scroll codec `prev_l1_message_queue_hash` |
    // assert_eq!(
    //     da_header.prev_l1_message_queue_hash,
    //     scroll_batch_info.prev_msg_queue_hash
    // );
    // // | `l1_message_queue_hash` | bytes (32) | Post-batch L1 message queue hash | Scroll codec `post_l1_message_queue_hash` |
    // assert_eq!(
    //     da_header.l1_message_queue_hash,
    //     scroll_batch_info.post_msg_queue_hash
    // );
}
