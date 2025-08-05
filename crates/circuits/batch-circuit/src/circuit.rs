use alloy_primitives::B256;

use scroll_zkvm_types_batch::ArchivedBatchWitness;
use scroll_zkvm_types_circuit::{
    AggCircuit, AggregationInput, Circuit, ProgramCommitment,
    io::read_witnesses,
    public_inputs::{
        batch::{BatchInfo, VersionedBatchInfo},
        chunk::VersionedChunkInfo,
    },
};

use crate::child_commitments;

#[allow(unused_imports, clippy::single_component_path_imports)]
use {
    openvm_algebra_guest::{IntMod, field::FieldExtension},
    openvm_ecc_guest::AffinePoint,
    openvm_keccak256_guest, // trigger extern native-keccak256
    openvm_pairing::bls12_381::{Bls12_381, Bls12_381G1Affine, Fp, Fp2},
    openvm_sha256_guest,
};

openvm::init!();

pub struct BatchCircuit;

impl Circuit for BatchCircuit {
    type Witness = ArchivedBatchWitness;

    type PublicInputs = VersionedBatchInfo;

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness {
        rkyv::access::<ArchivedBatchWitness, rkyv::rancor::BoxedError>(witness_bytes)
            .expect("BatchCircuit: rkyc deserialisation of witness bytes failed")
    }

    fn validate(witness: &Self::Witness) -> Self::PublicInputs {
        (BatchInfo::from(witness), (&witness.fork_name).into())
    }
}

impl AggCircuit for BatchCircuit {
    type AggregatedPublicInputs = VersionedChunkInfo;

    fn verify_commitments(commitment: &ProgramCommitment) {
        assert_eq!(
            commitment.leaf,
            child_commitments::LEAF_COMMIT,
            "mismatch chunk-proof leaf commitment: expected={:?}, got={:?}",
            child_commitments::LEAF_COMMIT,
            commitment.leaf,
        );
        assert_eq!(
            commitment.exe,
            child_commitments::EXE_COMMIT,
            "mismatch chunk-proof exe commitment: expected={:?}, got={:?}",
            child_commitments::EXE_COMMIT,
            commitment.exe,
        );
    }

    fn aggregated_public_inputs(witness: &Self::Witness) -> Vec<Self::AggregatedPublicInputs> {
        let fork_name = (&witness.fork_name).into();
        witness
            .chunk_infos
            .iter()
            .map(|archived| (archived.into(), fork_name))
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
