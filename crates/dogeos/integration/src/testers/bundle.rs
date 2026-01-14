use scroll_zkvm_integration::utils::metadata_from_batch_witnesses;
use scroll_zkvm_integration::{PROGRAM_COMMITMENTS, ProverTester};
use scroll_zkvm_types::dogeos::batch::dogeos::DogeOsBatchWitness;
use scroll_zkvm_types::dogeos::bundle::BundleWitness;
use scroll_zkvm_types::dogeos::bundle::dogeos::DogeOsBundleWitness;
use scroll_zkvm_types::public_inputs::dogeos::batch::{DogeOsBatchInfo, DogeOsBatchInfoExtras};
use scroll_zkvm_types::public_inputs::dogeos::bundle::DogeOsBundleInfo;
use scroll_zkvm_types::public_inputs::{ForkName, MultiVersionPublicInputs};
use scroll_zkvm_types::types_agg::AggregationInput;
use scroll_zkvm_types::version::Version;

pub struct BundleProverTester;

impl ProverTester for BundleProverTester {
    type Metadata = DogeOsBundleInfo;

    type Witness = DogeOsBundleWitness;

    const NAME: &str = "bundle";

    const PATH_PROJECT_ROOT: &str = "crates/dogeos/circuits/bundle-circuit";

    const DIR_ASSETS: &str = "bundle";
}

pub fn mock_bundle_witness(
    batch_witness: &DogeOsBatchWitness,
) -> eyre::Result<DogeOsBundleWitness> {
    let commitment = PROGRAM_COMMITMENTS["batch"];

    let info_inner = metadata_from_batch_witnesses(&batch_witness.inner)?;
    let info = DogeOsBatchInfo {
        inner: info_inner,
        extras: DogeOsBatchInfoExtras {},
    };

    let pi_hash = info.pi_hash_by_version(Version::feynman());

    let proof = AggregationInput {
        public_values: pi_hash
            .as_slice()
            .iter()
            .map(|&b| b as u32)
            .collect::<Vec<_>>(),
        commitment,
    };

    let bundle_witness = BundleWitness {
        version: Version::feynman().as_version_byte(),
        batch_infos: vec![info.inner],
        batch_proofs: vec![proof],
        fork_name: ForkName::Feynman,
    };

    Ok(DogeOsBundleWitness {
        inner: bundle_witness,
        batch_info_extras: vec![info.extras],
    })
}
