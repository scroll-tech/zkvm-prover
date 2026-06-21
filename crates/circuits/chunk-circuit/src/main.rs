use scroll_zkvm_types_chunk::Crypto;
use scroll_zkvm_types_circuit::{Circuit, public_inputs::PublicInputs, reveal_pi_hash};

mod circuit;
use circuit::ChunkCircuit as C;

openvm::entry!(main);

fn sha256_digest(input: &[u8], output: &mut [u8; 32]) {
    use openvm_sha2::Digest;
    *output = openvm_sha2::Sha256::digest(input).into();
}

fn main() {
    Crypto::install();

    ecies::sha256::set_digest_provider(|| {
        Box::new(ecies::sha256::ext::ExtSha256Core::new(
            sha256_digest,
        ))
    })
    .unwrap();

    let witness_bytes = C::read_witness_bytes();

    let witness = C::deserialize_witness(&witness_bytes);

    let public_inputs = C::validate(witness);

    reveal_pi_hash(public_inputs.pi_hash());
}
