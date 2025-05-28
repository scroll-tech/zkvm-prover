use scroll_zkvm_circuit_input_types_circuit::{
    Circuit, public_inputs::PublicInputs, reveal_pi_hash,
};

mod circuit;
use circuit::ChunkCircuit as C;

openvm::entry!(main);

fn main() {
    C::setup();

    let witness_bytes = C::read_witness_bytes();

    let witness = C::deserialize_witness(&witness_bytes);

    let public_inputs = C::validate(witness);

    reveal_pi_hash(public_inputs.pi_hash());
}
