use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types::{
    AggCircuit, Circuit,
    batch::{ArchivedBatchWitness, VersionedBatchInfo},
    chunk::VersionedChunkInfo,
    proof::{AggregationInput, ProgramCommitment},
    utils::read_witnesses,
};

#[allow(unused_imports, clippy::single_component_path_imports)]
use {
    openvm_algebra_guest::{IntMod, field::FieldExtension},
    openvm_ecc_guest::AffinePoint,
    openvm_keccak256_guest, // trigger extern native-keccak256
    openvm_pairing_guest::{
        bls12_381::{Bls12_381, Bls12_381G1Affine, Fp, Fp2},
        pairing::PairingCheck,
    },
    openvm_sha256_guest,
};

openvm_algebra_guest::moduli_macros::moduli_init! {
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
}
openvm_ecc_guest::sw_macros::sw_init! {
    Bls12_381G1Affine
}
openvm_algebra_complex_macros::complex_init! {
    Bls12_381Fp2 { mod_idx = 0 },
}

pub struct BatchCircuit;

impl Circuit for BatchCircuit {
    type Witness = ArchivedBatchWitness;

    type PublicInputs = VersionedBatchInfo;

    fn setup() {
        setup_all_complex_extensions();
        // barycentric require scalar field algebra so we setup all moduli,
        // not `setup_0` in openvm's example
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
        (
            crate::execute::execute(witness),
            (&witness.fork_name).into(),
        )
    }
}

impl AggCircuit for BatchCircuit {
    type AggregatedPublicInputs = VersionedChunkInfo;

    fn verify_commitments(commitment: &ProgramCommitment) {
        let match_rv32 = commitment.exe == crate::child_commitments_rv32::EXE_COMMIT
            && commitment.leaf == crate::child_commitments_rv32::LEAF_COMMIT;
        let match_openvm = commitment.exe == crate::child_commitments::EXE_COMMIT
            && commitment.leaf == crate::child_commitments::LEAF_COMMIT;
        println!(
            "verify_commitments: rv32 {}, openvm {}",
            match_rv32, match_openvm
        );
        assert!(
            match_rv32 || match_openvm,
            "mismatch chunk-proof commitments: expected={:?}, got={:?}",
            (
                (
                    crate::child_commitments_rv32::EXE_COMMIT,
                    crate::child_commitments_rv32::LEAF_COMMIT
                ),
                (
                    crate::child_commitments::EXE_COMMIT,
                    crate::child_commitments::LEAF_COMMIT
                )
            ),
            (commitment.exe, commitment.leaf),
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
