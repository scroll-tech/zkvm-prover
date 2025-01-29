use openvm_native_recursion::hints::Hintable;
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
use scroll_zkvm_circuit_input_types::proof::RootProofWithPublicValues;

use crate::proof::RootProof;

pub mod batch;

pub mod chunk;

pub mod bundle;

/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
pub trait ProvingTask {
    fn identifier(&self) -> String;

    fn to_witness_serialized(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error>;
}

pub fn flatten_root_proof(root_proof: &RootProof) -> RootProofWithPublicValues {
    let full_proof_streams = root_proof.write();

    let mut flattened_proof: Vec<u32> = Vec::new();
    for x in &full_proof_streams {
        flattened_proof.push(x.len() as u32);
        for f in x {
            flattened_proof.push(f.as_canonical_u32());
        }
    }

    let mut public_values = vec![];
    public_values.extend(
        root_proof
            .public_values
            .iter()
            .map(|x| x.as_canonical_u32()),
    );

    RootProofWithPublicValues {
        flattened_proof,
        public_values,
    }
}
