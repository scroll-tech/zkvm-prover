use alloy_primitives::B256;
use scroll_zkvm_types_bundle::BundleWitness;
use scroll_zkvm_types_circuit::{
    AggCircuit, AggregationInput, Circuit, ProgramCommitment,
    io::read_witnesses,
    public_inputs::{
        batch::VersionedBatchInfo,
        bundle::{BundleInfo, VersionedBundleInfo},
    },
};

use crate::child_commitments;

#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm_keccak256_guest;

#[derive(Default)]
pub struct BundleCircuit;

impl Circuit for BundleCircuit {
    type Witness = BundleWitness;

    type PublicInputs = VersionedBundleInfo;

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness {
        let config = bincode::config::standard();
        let (witness, _): (Self::Witness, _) =
            bincode::serde::decode_from_slice(witness_bytes, config).unwrap();
        Box::leak(Box::new(witness))
        // rkyv::access::<ArchivedBundleWitness, rkyv::rancor::BoxedError>(witness_bytes)
        //    .expect("BundleCircuit: rkyv deserialization of witness bytes failed")
    }

    fn validate(witness: &Self::Witness) -> Self::PublicInputs {
        (BundleInfo::from(witness), (witness.fork_name).clone())
    }
}

impl AggCircuit for BundleCircuit {
    type AggregatedPublicInputs = VersionedBatchInfo;

    fn verify_commitments(commitment: &ProgramCommitment) {
        assert_eq!(
            commitment.leaf,
            child_commitments::LEAF_COMMIT,
            "mismatch batch-proof leaf commitment: expected={:?}, got={:?}",
            child_commitments::LEAF_COMMIT,
            commitment.leaf,
        );
        assert_eq!(
            commitment.exe,
            child_commitments::EXE_COMMIT,
            "mismatch batch-proof exe commitment: expected={:?}, got={:?}",
            child_commitments::EXE_COMMIT,
            commitment.exe,
        );
    }

    fn aggregated_public_inputs(witness: &Self::Witness) -> Vec<Self::AggregatedPublicInputs> {
        let fork_name = (witness.fork_name).clone();
        witness
            .batch_infos
            .iter()
            .map(|archived| (archived.clone(), fork_name))
            .collect()
    }

    fn aggregated_pi_hashes(proofs: &[AggregationInput]) -> Vec<B256> {
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
