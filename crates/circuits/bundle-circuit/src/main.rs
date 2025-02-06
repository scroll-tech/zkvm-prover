use scroll_zkvm_circuit_input_types::{AggCircuit, Circuit};

mod circuit;
use circuit::BundleCircuit as C;

openvm::entry!(main);

#[rustfmt::skip]
mod child_commitments;
// The commitment to the batch program exe.
// const BATCH_EXE_COMMIT: [u32; 8] = [
// 385336439, 1505313270, 27681628, 120937705, 373468875, 938368382, 1052134188, 81732049,
// ];
//
// The commitment to the batch program leaf.
// const BATCH_LEAF_COMMIT: [u32; 8] = [
// 701140902, 366847636, 1087740927, 1189864384, 238260632, 233222120, 1487188715, 55637380,
// ];

fn main() {
    // Setup openvm extensions for the circuit.
    C::setup();

    // Read witness bytes from openvm StdIn.
    let witness_bytes = C::read_witness_bytes();

    // Deserialize witness bytes to the witness data type.
    let witness = C::deserialize_witness(&witness_bytes);

    // Verify the root proofs being aggregated in this circuit.
    let agg_proofs = C::verify_proofs(witness); // FIXME

    // Get the public-input values of the aggregated proofs from witness.
    let agg_pis = C::aggregated_public_inputs(witness);

    // Derive the digests of the public-input values of the proofs being aggregated.
    let agg_pi_hashes = C::aggregated_pi_hashes(&agg_proofs);

    // Validate that the pi hashes derived from the root proofs are in fact the digests of the
    // public-input values of the previous circuit layer.
    C::validate_aggregated_pi(&agg_pis, &agg_pi_hashes);

    // Validate the witness for the current circuit layer.
    let public_inputs = C::validate(witness);

    // Reveal the public-input values of the current circuit layer.
    C::reveal_pi(&public_inputs);
}
