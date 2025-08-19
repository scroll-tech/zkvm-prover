use scroll_zkvm_types_circuit::{AggCircuit, Circuit};

mod circuit;

type C = circuit::BundleCircuit;

// TODO: feature handling for feynman to use bundle info v3.

openvm::entry!(main);

mod child_commitments;

fn main() {
    // Read witness bytes from openvm StdIn.
    let witness_bytes = C::read_witness_bytes();

    // Deserialize witness bytes to the witness data type.
    let witness = C::deserialize_witness(&witness_bytes);

    // Verify the root proofs being aggregated in the circuit.
    let agg_proofs = C::verify_proofs(witness);

    // Get the public-input values of the proofs being aggregated from witness.
    let agg_pis = C::aggregated_public_inputs(witness);

    // Derive the digests of the public-input values of the proofs being aggregated.
    let agg_pi_hashes = C::aggregated_pi_hashes(&agg_proofs);

    // Validate that the pi hashes derived from the stark proofs are in fact the digests of the
    // public-input values of the previous circuit layer.
    C::validate_aggregated_pi(&agg_pis, &agg_pi_hashes);

    // Validate the witness for the current circuit layer.
    let public_inputs = C::validate(witness);

    // Reveal the public input values of the current circuit layer.
    C::reveal_pi(&public_inputs);
}
