use scroll_zkvm_circuit_input_types::{AggCircuit, Circuit};

mod batch;

mod blob_consistency;

mod circuit;
use circuit::BatchCircuit as C;

mod execute;

mod payload;

mod utils;

openvm::entry!(main);

fn main() {
    // Setup openvm extensions for the circuit.
    C::setup();

    // Read witness bytes from openvm StdIn.
    let witness_bytes = C::read_witness_bytes();

    // Deserialize witness bytes to the witness data type.
    let witness = C::deserialize_witness(&witness_bytes);

    // Verify the root proofs from the previous circuit layer.
    let prev_proofs = C::verify_proofs(witness);

    // Get the previous circuit layer's public-input values.
    let prev_pis = C::prev_public_inputs(witness);

    // Derive the digests of the public-input values of the previous circuit layer.
    let prev_pi_hashes = C::deserialize_prev_pi_hashes(&prev_proofs);

    // Validate that the pi hashes derived from the root proofs are in fact the digests of the
    // public-input values of the previous circuit layer.
    C::validate_prev_pi(&prev_pis, &prev_pi_hashes);

    // Validate the witness for the current circuit layer.
    let public_inputs = C::validate(witness);

    // Reveal the public-input values of the current circuit layer.
    C::reveal_pi(&public_inputs);
}
