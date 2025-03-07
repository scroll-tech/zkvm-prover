use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types::{
    AggCircuit, Circuit,
    batch::{ArchivedBatchWitness, BatchInfo},
    chunk::ChunkInfo,
    proof::{AggregationInput, ProgramCommitment},
    utils::read_witnesses,
};

use crate::child_commitments::{EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT};
#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm_keccak256_guest; // trigger extern native-keccak256

openvm_algebra_guest::moduli_macros::moduli_init! {
    "52435875175126190479447740508185965837690552500527637822603658699938581184513"
}

pub struct BatchCircuit;

impl Circuit for BatchCircuit {
    type Witness = ArchivedBatchWitness;

    type PublicInputs = BatchInfo;

    fn setup() {
        setup_all_moduli();
    }

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness {
        rkyv::access::<ArchivedBatchWitness, rkyv::rancor::BoxedError>(witness_bytes)
            .expect("BatchCircuit: rkyc deserialisation of witness bytes failed")
    }

    fn validate(witness: &Self::Witness) -> Self::PublicInputs {
        crate::execute::execute(witness)
    }
}

impl AggCircuit for BatchCircuit {
    type AggregatedPublicInputs = ChunkInfo;

    fn verify_commitments(commitment: &ProgramCommitment) {
        if commitment.exe != CHUNK_EXE_COMMIT {
            panic!(
                "mismatch chunk-proof exe commitment: expected={:?}, got={:?}",
                CHUNK_EXE_COMMIT, commitment.exe,
            );
        }
        if commitment.leaf != CHUNK_LEAF_COMMIT {
            panic!(
                "mismatch chunk-proof leaf commitment: expected={:?}, got={:?}",
                CHUNK_EXE_COMMIT, commitment.leaf,
            );
        }
    }

    fn aggregated_public_inputs(witness: &Self::Witness) -> Vec<Self::AggregatedPublicInputs> {
        witness
            .chunk_infos
            .iter()
            .map(|archived| archived.into())
            .collect()
    }

    fn aggregated_pi_hashes(proofs: &[AggregationInput]) -> Vec<alloy_primitives::B256> {
        proofs
            .iter()
            .map(|proof| {
                let transformed = proof
                    .public_values
                    .iter()
                    .map(|&val| u8::try_from(val).expect("0 < public value < 256"))
                    .collect::<Vec<u8>>();
                B256::from_slice(transformed.as_slice())
            })
            .collect()
    }
}
