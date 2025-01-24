mod execute;
use execute::execute;

mod utils;
use utils::{deserialize_witness, read_witness};

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
    setup_all_moduli();
    setup_all_curves();
    setup_all_complex_extensions();

    let witness_bytes = read_witness(); // openvm::io::read_vec();

    let witness = deserialize_witness(witness_bytes);

    let public_input_hash = execute(witness.as_slice());

    for (i, part) in public_input_hash.chunks_exact(4).enumerate() {
        openvm::io::reveal(u32::from_be_bytes(part.try_into().unwrap()), i)
    }
}
