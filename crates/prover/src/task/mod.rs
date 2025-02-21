use openvm_sdk::StdIn;
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
use scroll_zkvm_circuit_input_types::proof::{AggregationInput, ProgramCommitment};

use crate::proof::{RootProof, WrappedProof};

pub mod batch;

pub mod chunk;

pub mod bundle;

/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
pub trait ProvingTask: serde::de::DeserializeOwned {
    fn identifier(&self) -> String;

    fn build_guest_input(&self) -> Result<StdIn, rkyv::rancor::Error>;
}

/// Flatten a [`WrappedProof`] and split the proof from the public values. We also split out the
/// program commitments.
pub fn flatten_wrapped_proof<Metadata>(
    wrapped_proof: &WrappedProof<Metadata, RootProof>,
) -> AggregationInput {
    let public_values = wrapped_proof
        .proof
        .public_values
        .iter()
        .map(|x| x.as_canonical_u32())
        .collect();
    let commitment = ProgramCommitment::deserialize(&wrapped_proof.vk);

    AggregationInput {
        public_values,
        commitment,
    }
}
