use alloy_primitives::B256;
use scroll_zkvm_types_batch::dogeos::{DogeOsBatchWitness};
use scroll_zkvm_types_circuit::{
    AggCircuit, AggregationInput, Circuit, ProgramCommitment,
    io::read_witnesses,
    public_inputs::{
        Version,
        dogeos::{
            batch::{DogeOsBatchInfo, VersionedDogeOsBatchInfo},
            chunk::VersionedDogeOsChunkInfo,
        },
    },
};
use itertools::Itertools;

use crate::child_commitments;

#[allow(unused_imports, clippy::single_component_path_imports)]
use {
    openvm_algebra_guest::{IntMod, field::FieldExtension},
    openvm_ecc_guest::AffinePoint,
    openvm_keccak256_guest, // trigger extern native-keccak256
    openvm_pairing::bls12_381::{Bls12_381, Bls12_381G1Affine, Fp, Fp2},
    openvm_sha256_guest,
};
use scroll_zkvm_types_circuit::public_inputs::dogeos::chunk::DogeOsChunkInfo;

openvm::init!();

pub struct BatchCircuit;

impl Circuit for BatchCircuit {
    type Witness = DogeOsBatchWitness;

    type PublicInputs = VersionedDogeOsBatchInfo;

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> Self::Witness {
        let config = bincode::config::standard();
        let (witness, _): (Self::Witness, _) =
            bincode::serde::decode_from_slice(witness_bytes, config)
                .expect("BatchCircuit: deserialisation of witness bytes failed");
        witness
    }

    fn validate(witness: Self::Witness) -> Self::PublicInputs {
        let version = Version::from(witness.inner.version);
        assert_eq!(version.fork, witness.inner.fork_name);

        (DogeOsBatchInfo::from(&witness), version)
    }
}

impl AggCircuit for BatchCircuit {
    type AggregatedPublicInputs = VersionedDogeOsChunkInfo;

    fn verify_commitments(commitment: &ProgramCommitment) {
        assert_eq!(
            commitment.vm,
            child_commitments::VM_COMMIT,
            "mismatch chunk-proof leaf commitment: expected={:?}, got={:?}",
            child_commitments::VM_COMMIT,
            commitment.vm,
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
        let version = Version::from(witness.inner.version);
        witness
            .inner
            .chunk_infos
            .iter()
            .cloned()
            .zip_eq(witness.extras.chunk_info_extras.iter().cloned())
            .map(DogeOsChunkInfo::from)
            .map(|chunk_info| (chunk_info, version))
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
