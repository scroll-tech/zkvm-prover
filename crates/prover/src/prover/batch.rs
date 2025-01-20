use openvm_sdk::config::SdkVmConfig;

use crate::Prover;

/// Prover for [`BatchCircuit`].
pub type BatchProver = Prover<SdkVmConfig>;
