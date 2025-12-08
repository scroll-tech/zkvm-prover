use alloy_primitives::B256;
use scroll_zkvm_types_bundle::dogeos::DogeOsBundleWitness;
use scroll_zkvm_types_circuit::{
    AggCircuit, AggregationInput, Circuit, ProgramCommitment,
    io::read_witnesses,
    public_inputs::{
        Version,
        dogeos::{
            batch::{VersionedDogeOsBatchInfo, DogeOsBatchInfo},
            bundle::{DogeOsBundleInfo, VersionedDogeOsBundleInfo},
        },
    },
};

use crate::child_commitments;

#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm_keccak256_guest;

#[derive(Default)]
pub struct BundleCircuit;

impl Circuit for BundleCircuit {
    type Witness = DogeOsBundleWitness;

    type PublicInputs = VersionedDogeOsBundleInfo;

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> Self::Witness {
        let config = bincode::config::standard();
        let (witness, _): (Self::Witness, _) =
            bincode::serde::decode_from_slice(witness_bytes, config)
                .expect("BundleCircuit: deserialization of witness bytes failed");
        witness
    }

    fn validate(witness: Self::Witness) -> Self::PublicInputs {
        let version = Version::from(witness.inner.version);
        assert_eq!(version.fork, witness.inner.fork_name);

        (DogeOsBundleInfo::from(&witness), version)
    }
}

impl AggCircuit for BundleCircuit {
    type AggregatedPublicInputs = VersionedDogeOsBatchInfo;

    fn verify_commitments(commitment: &ProgramCommitment) {
        assert_eq!(
            commitment.vm,
            child_commitments::VM_COMMIT,
            "mismatch batch-proof leaf commitment: expected={:?}, got={:?}",
            child_commitments::VM_COMMIT,
            commitment.vm,
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
        let version = Version::from(witness.inner.version);
        witness
            .inner
            .batch_infos
            .iter()
            .cloned()
            .map(|inner| DogeOsBatchInfo { inner })
            .map(|batch_info| (batch_info, version))
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
