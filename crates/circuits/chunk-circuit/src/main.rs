use scroll_zkvm_types_circuit::{Circuit, public_inputs::PublicInputs, reveal_pi_hash};

mod circuit;
use circuit::ChunkCircuit as C;

openvm::entry!(main);

fn main() {
    ecies::sha256::set_digest_provider(|| {
        Box::new(ecies::sha256::ext::ExtSha256Core::new(
            openvm_sha2::set_sha256,
        ))
    })
    .unwrap();

    let witness_bytes = C::read_witness_bytes();

    let witness = C::deserialize_witness(&witness_bytes);

    let public_inputs = C::validate(witness);

    reveal_pi_hash(public_inputs.pi_hash());
}
