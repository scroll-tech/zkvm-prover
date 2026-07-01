use alloc::vec::Vec;
pub use scroll_zkvm_types_base::public_inputs::PublicInputs;

/// Minimal circuit abstraction for SP1 guest programs.
///
/// Mirrors the host-visible shape of `scroll_zkvm_types_circuit::Circuit` but
/// without OpenVM-specific I/O or aggregation assumptions.
pub trait Circuit {
    type Witness;
    type PublicInputs: PublicInputs;

    fn read_witness_bytes() -> Vec<u8> {
        sp1_zkvm::io::read_vec()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> Self::Witness;

    fn validate(witness: Self::Witness) -> Self::PublicInputs;
}
