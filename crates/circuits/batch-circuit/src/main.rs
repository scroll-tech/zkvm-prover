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
    C::setup();

    let witness_bytes = C::read_witness_bytes();

    let witness = C::deserialize_witness(&witness_bytes);

    let prev_pis = C::prev_public_inputs(witness);

    let prev_proofs = C::verify_proofs(witness);

    let prev_pi_hashes = C::deserialize_prev_pi_hashes(&prev_proofs);

    C::validate_prev_pi(&prev_pis, &prev_pi_hashes);

    let public_inputs = C::validate(witness);

    C::reveal_pi(&public_inputs);
}
