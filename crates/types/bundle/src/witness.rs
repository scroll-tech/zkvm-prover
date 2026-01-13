use types_base::{
    aggregation::{AggregationInput, ProofCarryingWitness},
    fork_name::ForkName,
    public_inputs::scroll::{batch::BatchInfo, bundle::BundleInfo},
};

/// The witness for the bundle circuit.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct BundleWitness {
    /// The version byte as per [version][types_base::version].
    pub version: u8,
    /// Batch proofs being aggregated in the bundle.
    pub batch_proofs: Vec<AggregationInput>,
    /// Public-input values for the corresponding batch proofs.
    pub batch_infos: Vec<BatchInfo>,
    /// The code version specify the chain spec
    pub fork_name: ForkName,
}

impl ProofCarryingWitness for BundleWitness {
    fn get_proofs(&self) -> Vec<AggregationInput> {
        self.batch_proofs.clone()
    }
}

impl From<&BundleWitness> for BundleInfo {
    fn from(witness: &BundleWitness) -> Self {
        assert!(
            !witness.batch_infos.is_empty(),
            "at least one batch in a bundle"
        );

        let (first_batch, last_batch) = (
            witness
                .batch_infos
                .first()
                .expect("at least one batch in bundle"),
            witness
                .batch_infos
                .last()
                .expect("at least one batch in bundle"),
        );

        let chain_id = first_batch.chain_id;
        let num_batches = u32::try_from(witness.batch_infos.len()).expect("num_batches: u32");
        let prev_state_root = first_batch.parent_state_root;
        let prev_batch_hash = first_batch.parent_batch_hash;
        let post_state_root = last_batch.state_root;
        let batch_hash = last_batch.batch_hash;
        let withdraw_root = last_batch.withdraw_root;
        let msg_queue_hash = last_batch.post_msg_queue_hash;

        BundleInfo {
            chain_id,
            num_batches,
            prev_state_root,
            prev_batch_hash,
            post_state_root,
            batch_hash,
            withdraw_root,
            msg_queue_hash,
            encryption_key: first_batch.encryption_key.clone(),
        }
    }
}
