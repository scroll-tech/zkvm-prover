use scroll_zkvm_circuit_input_types::{AggCircuit, Circuit};

mod blob_consistency;

mod builder;

mod circuit;
use circuit::BatchCircuit as C;

mod execute;

mod payload;

openvm::entry!(main);

#[rustfmt::skip]
mod child_commitments;
use child_commitments::{EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT};

// The commitment to the chunk program exe.
// const CHUNK_EXE_COMMIT: [u32; 8] = [
// 1233178528, 835863246, 185337613, 1062380745, 1006025895, 1800931371, 848508197, 1288278302,
// ];
//
// The commitment to the chunk program leaf.
// const CHUNK_LEAF_COMMIT: [u32; 8] = [
// 1306725861, 917524666, 1051090997, 1927035141, 671332224, 1674673970, 495361509, 1117197118,
// ];

fn main() {
    // Setup openvm extensions for the circuit.
    C::setup();

    // Read witness bytes from openvm StdIn.
    let witness_bytes = C::read_witness_bytes();

    // Deserialize witness bytes to the witness data type.
    let witness = C::deserialize_witness(&witness_bytes);

    // Verify the root proofs being aggregated in the circuit.
    let agg_proofs = C::verify_proofs(witness, [CHUNK_EXE_COMMIT, CHUNK_LEAF_COMMIT]);

    // Get the public-input values of the proofs being aggregated from witness.
    let agg_pis = C::aggregated_public_inputs(witness);

    // Derive the digests of the public-input values of proofs being aggregated.
    let agg_pi_hashes = C::aggregated_pi_hashes(&agg_proofs);

    // Validate that the pi hashes derived from the root proofs are in fact the digests of the
    // public-input values of the previous circuit layer.
    C::validate_aggregated_pi(&agg_pis, &agg_pi_hashes);

    // Validate the witness for the current circuit layer.
    let public_inputs = C::validate(witness);

    // Reveal the public-input values of the current circuit layer.
    C::reveal_pi(&public_inputs);
}
