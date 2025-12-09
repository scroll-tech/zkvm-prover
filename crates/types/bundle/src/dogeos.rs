use types_base::aggregation::{AggregationInput, ProofCarryingWitness};
use types_base::public_inputs::dogeos::batch::DogeOsBatchInfoExtras;
use types_base::public_inputs::dogeos::bundle::DogeOsBundleInfo;

/// The witness for the bundle circuit.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DogeOsBundleWitness {
    pub inner: crate::BundleWitness,
    pub batch_info_extras: Vec<DogeOsBatchInfoExtras>,
}

impl From<(crate::BundleWitness, Vec<DogeOsBatchInfoExtras>)> for DogeOsBundleWitness {
    fn from(value: (crate::BundleWitness, Vec<DogeOsBatchInfoExtras>)) -> Self {
        Self {
            inner: value.0,
            batch_info_extras: value.1,
        }
    }
}

impl ProofCarryingWitness for DogeOsBundleWitness {
    fn get_proofs(&self) -> Vec<AggregationInput> {
        self.inner.batch_proofs.clone()
    }
}

impl From<&DogeOsBundleWitness> for DogeOsBundleInfo {
    fn from(witness: &DogeOsBundleWitness) -> Self {
        let scroll_bundle_info =
            types_base::public_inputs::scroll::bundle::BundleInfo::from(&witness.inner);
        DogeOsBundleInfo {
            inner: scroll_bundle_info,
        }
    }
}
