use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types::{
    AggCircuit, Circuit, ProofCarryingWitness, PublicInputs,
    bundle::{ArchivedBundleWitness, BatchInfo, BundleInfo},
    proof::RootProofWithPublicValues,
};

#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm_keccak256_guest;

use crate::utils::read_witnesses; // trigger extern native-keccak256

openvm_algebra_guest::moduli_macros::moduli_init! {
    "52435875175126190479447740508185965837690552500527637822603658699938581184513"
}

const EXE_COMMIT: [u32; 8] = [
    397570296, 303176697, 1964773027, 1141065112, 1871270311, 1130635204, 1728891034, 568787834,
];

const LEAF_COMMIT: [u32; 8] = [
    1927402829, 499234175, 923282328, 1081788839, 582968208, 549279052, 209451000, 2007289153,
];

const NUM_PUBLIC_VALUES: usize = 32;

fn exec_kernel(input: &[u32], expect_output: &[u32]) {
    let mut _input_ptr: *const u32 = input.as_ptr();
    let mut _output_ptr: *const u32 = expect_output.as_ptr();
    let mut _buf1: u32 = 0;
    let mut _buf2: u32 = 0;
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    unsafe {
        std::arch::asm!(
            include_str!("../../../tools/generate-verifier-asm/root_verifier.asm"),
            inout("x28") _input_ptr,
            inout("x29") _output_ptr,
            inout("x30") _buf1,
            inout("x31") _buf2,
        )
    }
}

fn verify_chunk_proof(flatten_proof: &[u32], public_inputs: &[u32]) {
    assert_eq!(public_inputs.len(), NUM_PUBLIC_VALUES);
    let mut full_pi = vec![];
    full_pi.extend(EXE_COMMIT);
    full_pi.extend(LEAF_COMMIT);
    full_pi.extend_from_slice(public_inputs);
    exec_kernel(flatten_proof, &full_pi);
}

pub struct BundleCircuit;

impl Circuit for BundleCircuit {
    type Witness = ArchivedBundleWitness;

    type PublicInputs = BundleInfo;

    type PrevPublicInputs = BatchInfo;

    fn setup() {
        setup_all_moduli();
    }

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness {
        rkyv::access::<ArchivedBundleWitness, rkyv::rancor::BoxedError>(witness_bytes)
            .expect("BundleCircuit: rkyv deserialization of witness bytes failed")
    }

    fn validate(_witness: &Self::Witness) -> Self::PublicInputs {
        unimplemented!()
    }
}

impl AggCircuit for BundleCircuit {
    fn prev_public_inputs(witness: &Self::Witness) -> Vec<Self::PrevPublicInputs> {
        witness
            .batch_infos
            .iter()
            .map(|archived| archived.into())
            .collect()
    }

    fn verify_proofs(witness: &Self::Witness) -> Vec<RootProofWithPublicValues> {
        let prev_proofs = witness.get_proofs();

        for proof in prev_proofs.iter() {
            verify_chunk_proof(
                proof.flattened_proof.as_slice(),
                proof.public_values.as_slice(),
            );
        }

        prev_proofs
    }

    fn deserialize_prev_pi_hashes(proofs: &[RootProofWithPublicValues]) -> Vec<B256> {
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

    fn validate_prev_pi(prev_pis: &[Self::PrevPublicInputs], prev_pi_hashes: &[B256]) {
        for (prev_pi, &prev_pi_hash) in prev_pis.iter().zip(prev_pi_hashes.iter()) {
            assert_eq!(prev_pi.pi_hash(), prev_pi_hash);
        }
    }
}
