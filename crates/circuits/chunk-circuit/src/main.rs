mod execute;
use execute::execute;

mod utils;
use utils::{deserialize_witness, read_witnesses};

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

openvm::entry!(main);

fn main() {
    use ChunkCircuit as C;

    C::setup();

    let witness_bytes = C::read_witness_bytes();

    let witness = C::deserialize_witness(&witness_bytes);

    let public_inputs = C::validate(witness);

    C::reveal_pi(&public_inputs);
}

use rkyv::vec::ArchivedVec;
use sbv::primitives::{B256, types::ArchivedBlockWitness};

const CHUNK_SIZE: usize = 4;

pub trait PublicInputs {
    /// Keccak-256 digest of the public inputs.
    fn pi_hash(&self) -> B256;
    /// Validation logic between public inputs of two contiguous instances.
    fn validate(&self, prev_pi: &Self);
}

pub trait Circuit {
    /// Whether or not this circuit aggregates [STARK proofs][root_proof] from the previous layer's
    /// circuit.
    const IS_AGG: bool;
    /// The witness provided to the circuit.
    type Witness;
    /// The public-input values for the circuit.
    type PublicInputs: PublicInputs;
    /// The public-input values from the previous layer's circuit, that must be validated in the
    /// current circuit.
    type PrevPublicInputs: PublicInputs;
    /// Setup openvm extensions as a preliminary step.
    fn setup();
    /// Reads bytes from openvm StdIn.
    fn read_witness_bytes() -> Vec<u8>;
    /// Deserialize raw bytes into the circuit's witness type.
    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness;
    /// Derive the public-input values of the previous layer's circuit from the current circuit's
    /// witness. Since the current possibly aggregates several of those proofs, we return a [`Vec`]
    /// of the previous circuit's public-input values.
    fn prev_public_inputs(witness: &Self::Witness) -> Vec<Self::PrevPublicInputs>;
    /// Validate the witness to produce the circuit's public inputs.
    fn validate(witness: &Self::Witness) -> Self::PublicInputs;
    /// Reveal the public inputs.
    fn reveal_pi(pi: &Self::PublicInputs) {
        for (i, part) in pi.pi_hash().chunks_exact(CHUNK_SIZE).enumerate() {
            let value = u32::from_le_bytes(part.try_into().unwrap());
            openvm::io::print(format!("pi[{i}] = {value:?}"));
            openvm::io::reveal(value, i)
        }
    }
}

pub struct ChunkCircuit;

impl Circuit for ChunkCircuit {
    const IS_AGG: bool = false;

    type Witness = ArchivedVec<ArchivedBlockWitness>;

    type PublicInputs = ChunkPublicInputs;

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
        deserialize_witness(witness_bytes)
    }

    fn prev_public_inputs(_witness: &Self::Witness) -> Vec<Self::PrevPublicInputs> {
        unreachable!("ChunkCircuit does not aggregate proofs");
    }

    fn validate(witness: &Self::Witness) -> Self::PublicInputs {
        execute(witness)
    }
}

pub struct ChunkPublicInputs {
    pub chain_id: u64,
    pub prev_state_root: B256,
    pub post_state_root: B256,
    pub withdraw_root: B256,
    pub data_hash: B256,
    pub tx_data_digest: B256,
}

impl PublicInputs for ChunkPublicInputs {
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

impl PublicInputs for () {
    fn pi_hash(&self) -> B256 {
        unreachable!("PublicInputs::pi_hash for ()");
    }
    fn validate(&self, _prev_pi: &Self) {
        unreachable!("PublicInputs::validate for ()");
    }
}
