use scroll_zkvm_circuit_input_types::Circuit;

mod circuit;
use circuit::ChunkCircuit as C;

mod execute;

mod utils;

openvm::entry!(main);

fn main() {
    C::setup();

    let witness_bytes = C::read_witness_bytes();

    let witness = C::deserialize_witness(&witness_bytes);

    let public_inputs = C::validate(witness);

    C::reveal_pi(&public_inputs);
}
