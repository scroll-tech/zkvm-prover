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
        let scroll_batch_info = scroll::batch::BatchInfo::from(&witness.inner);
        verify_da_inclusion(witness, &scroll_batch_info);


        DogeOsBatchInfo {
            inner: scroll_batch_info,
        }
    }
}


fn verify_da_inclusion(
    witness: &DogeOsBatchWitness,
    scroll_batch_info: &scroll::batch::BatchInfo,
) {
    DaInclusionVerifier.verify_envelope(
        &witness.extras.inclusion,
        &witness.extras.verifier_context,
    ).expect("failed to verify inclusion proof");

    let (first_chunk_extras, last_chunk_extras) = (
        witness.extras.chunk_info_extras.first().expect("at least one chunk in batch"),
        witness.extras.chunk_info_extras.last().expect("at least one chunk in batch"),
    );

    let da_header = &witness.extras.inclusion.artifact.v2_header;

    // See: https://github.com/DogeOS69/dogeos-core/tree/feat/trust-minimized-bridge-crates/crates/common_types/src/protos#blobheader-v2-fields-wip
    // | Field | Type / Size | Meaning | Source / Notes |
    // |-------|-------------|---------|----------------|
    // | `prev_state_root` | bytes (32) | L2 state root before batch | DogeOS RPC |
    assert_eq!(da_header.prev_state_root, scroll_batch_info.parent_state_root);
    // | `state_root` | bytes (32) | L2 state root after batch | DogeOS RPC |
    assert_eq!(da_header.state_root, scroll_batch_info.state_root);
    // | `prev_batch_hash` | bytes (32) | Hash of previous batch | From `commitBatches` inputs |
    assert_eq!(da_header.prev_batch_hash, scroll_batch_info.parent_batch_hash); // FIXME: is this same thing?
    // | `batch_hash` | bytes (32) | Hash of current batch | `calculate_batch_hash` (codec version, batch index, blob commitment, prev batch hash) |
    assert_eq!(da_header.batch_hash, scroll_batch_info.batch_hash); // FIXME: is this same thing?
    // | `prev_l1_message_queue_hash` | bytes (32) | Pre-batch queue hash | Scroll codec `prev_l1_message_queue_hash` |
    assert_eq!(da_header.prev_l1_message_queue_hash, scroll_batch_info.prev_msg_queue_hash);
    // | `l1_message_queue_hash` | bytes (32) | Post-batch L1 message queue hash | Scroll codec `post_l1_message_queue_hash` |
    assert_eq!(da_header.l1_message_queue_hash, scroll_batch_info.post_msg_queue_hash);
    // | `deposit_queue_block_hash` | bytes (32) | Dogecoin block hash at current deposit queue height | From Dogecoin indexer / `l1_interface` |
    assert_eq!(da_header.prev_deposit_queue_block_hash, first_chunk_extras.start_blockhash);
    assert_eq!(da_header.deposit_queue_block_hash, last_chunk_extras.end_blockhash);

}
