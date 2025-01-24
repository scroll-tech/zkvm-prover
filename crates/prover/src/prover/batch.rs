use crate::Prover;

use super::types::BatchProverType;

/// Prover for [`BatchCircuit`].
pub type BatchProver = Prover<BatchProverType>;
