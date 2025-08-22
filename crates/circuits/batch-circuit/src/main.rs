use scroll_zkvm_types_circuit::{AggCircuit, Circuit};

mod circuit;
use circuit::BatchCircuit as C;

mod child_commitments;

openvm::entry!(main);

fn main() {
    println!("0000");
    // Read witness bytes from openvm StdIn.
    let witness_bytes = C::read_witness_bytes();

    // Deserialize witness bytes to the witness data type.
    println!("0001");
    let witness = C::deserialize_witness(&witness_bytes);

    // Verify the root proofs being aggregated in the circuit.
    let agg_proofs = C::verify_proofs(&witness);

    // Get the public-input values of the proofs being aggregated from witness.
    let agg_pis = C::aggregated_public_inputs(&witness);

    // Derive the digests of the public-input values of proofs being aggregated.

    println!("0004");
    let agg_pi_hashes = C::aggregated_pi_hashes(&agg_proofs);

    // Validate that the pi hashes derived from the root proofs are in fact the digests of the
    // public-input values of the previous circuit layer.

    println!("0005");
    C::validate_aggregated_pi(&agg_pis, &agg_pi_hashes);

    // Validate the witness for the current circuit layer.

    println!("0006");
    let public_inputs = C::validate(witness);

    println!("0007");
    // Reveal the public-input values of the current circuit layer.
    C::reveal_pi(&public_inputs);
}
