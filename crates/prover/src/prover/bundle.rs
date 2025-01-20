use openvm_sdk::config::SdkVmConfig;

use crate::Prover;

/// Prover for [`BundleCircuit`].
pub type BundleProver = Prover<SdkVmConfig>;
