use rkyv::vec::ArchivedVec;
use sbv::primitives::{B256, types::ArchivedBlockWitness};
use scroll_zkvm_circuit_input_types::{Circuit, PublicInputs};

use crate::{execute::execute, utils::read_witnesses};

#[allow(unused_imports, clippy::single_component_path_imports)]
use {
    openvm::platform as openvm_platform,
    openvm_algebra_guest::IntMod,
    openvm_bigint_guest, // trigger extern u256 (this may be unneeded)
    openvm_ecc_guest::k256::Secp256k1Point,
    openvm_keccak256_guest, // trigger extern native-keccak256
    openvm_pairing_guest::bn254::Bn254G1Affine,
};

openvm_algebra_guest::moduli_macros::moduli_init! {
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", // Bn254Fp Coordinate field
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", // Bn254 Scalar
    "0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F", // secp256k1 Coordinate field
    "0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141" // secp256k1 Scalar field
}
openvm_ecc_guest::sw_macros::sw_init! {
    Secp256k1Point,
    Bn254G1Affine
}
openvm_algebra_complex_macros::complex_init! {
    Bn254Fp2 { mod_idx = 0 },
}

pub struct ChunkCircuit;

impl Circuit for ChunkCircuit {
    const IS_AGG: bool = false;

    type Witness = ArchivedVec<ArchivedBlockWitness>;

    type PublicInputs = ChunkCircuitPublicInputs;

    type PrevPublicInputs = ();

    fn setup() {
        setup_all_moduli();
        setup_all_curves();
        setup_all_complex_extensions();
    }

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness {
        rkyv::access::<ArchivedVec<ArchivedBlockWitness>, rkyv::rancor::BoxedError>(witness_bytes)
            .unwrap()
    }

    fn prev_public_inputs(_witness: &Self::Witness) -> Vec<Self::PrevPublicInputs> {
        unreachable!("ChunkCircuit does not aggregate proofs");
    }

    fn validate(witness: &Self::Witness) -> Self::PublicInputs {
        execute(witness)
    }
}

pub struct ChunkCircuitPublicInputs {
    pub chain_id: u64,
    pub prev_state_root: B256,
    pub post_state_root: B256,
    pub withdraw_root: B256,
    pub data_hash: B256,
    pub tx_data_digest: B256,
}

impl PublicInputs for ChunkCircuitPublicInputs {
    /// Public input hash for a given chunk is defined as
    ///
    /// keccak(
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     chunk data hash ||
    ///     chunk txdata hash
    /// )
    fn pi_hash(&self) -> B256 {
        scroll_zkvm_circuit_input_types::utils::keccak256(
            std::iter::empty()
                .chain(&self.chain_id.to_be_bytes())
                .chain(self.prev_state_root.as_slice())
                .chain(self.post_state_root.as_slice())
                .chain(self.withdraw_root.as_slice())
                .chain(self.data_hash.as_slice())
                .chain(self.tx_data_digest.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    /// Validate public inputs between 2 contiguous chunks.
    ///
    /// - chain id MUST match
    /// - state roots MUST be chained
    fn validate(&self, prev_pi: &Self) {
        assert_eq!(self.chain_id, prev_pi.chain_id);
        assert_eq!(self.prev_state_root, prev_pi.post_state_root);
    }
}
