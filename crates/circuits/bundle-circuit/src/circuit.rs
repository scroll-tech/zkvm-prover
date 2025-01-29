use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types::{
    AggCircuit, Circuit,
    batch::BatchInfo,
    bundle::{ArchivedBundleWitness, BundleInfo},
    proof::RootProofWithPublicValues,
    utils::read_witnesses,
};

#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm_keccak256_guest;

openvm_algebra_guest::moduli_macros::moduli_init! {
    "52435875175126190479447740508185965837690552500527637822603658699938581184513"
}

pub struct BundleCircuit;

impl Circuit for BundleCircuit {
    type Witness = ArchivedBundleWitness;

    type PublicInputs = BundleInfo;

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
    type AggregatedPublicInputs = BatchInfo;

    fn prev_public_inputs(witness: &Self::Witness) -> Vec<Self::AggregatedPublicInputs> {
        witness
            .batch_infos
            .iter()
            .map(|archived| archived.into())
            .collect()
    }

    fn derive_prev_pi_hashes(proofs: &[RootProofWithPublicValues]) -> Vec<B256> {
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
