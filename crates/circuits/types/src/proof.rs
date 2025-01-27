/// Represents an openvm root proof with the proof and public values flattened.
#[derive(
    Clone,
    Debug,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct RootProofWithPublicValues {
    /// Flattened proof bytes.
    pub flattened_proof: Vec<u32>,
    /// Flattened public values.
    pub public_values: Vec<u32>,
}

/// The commitment to the root verifier's exe.
const EXE_COMMIT: [u32; 8] = [
    397570296, 303176697, 1964773027, 1141065112, 1871270311, 1130635204, 1728891034, 568787834,
];

/// The commitment to the root verifier's leaf.
const LEAF_COMMIT: [u32; 8] = [
    1927402829, 499234175, 923282328, 1081788839, 582968208, 549279052, 209451000, 2007289153,
];

/// Number of public-input values, i.e. [u32; N].
///
/// Note that the actual value for each u32 is a byte.
const NUM_PUBLIC_VALUES: usize = 32;

/// Verify a root proof.
pub fn verify_proof(flattened_proof: &[u32], public_inputs: &[u32]) {
    // Sanity check for the number of public-input values.
    assert_eq!(public_inputs.len(), NUM_PUBLIC_VALUES);

    // Extend the public-input values by prepending the commitments to the root verifier's exe and
    // leaf.
    let mut extended_public_inputs = vec![];
    extended_public_inputs.extend(EXE_COMMIT);
    extended_public_inputs.extend(LEAF_COMMIT);
    extended_public_inputs.extend_from_slice(public_inputs);

    // Pass through kernel and verify against root verifier's ASM.
    exec_kernel(flattened_proof, &extended_public_inputs);
}

fn exec_kernel(input: &[u32], output: &[u32]) {
    let mut _input_ptr: *const u32 = input.as_ptr();
    let mut _output_ptr: *const u32 = output.as_ptr();
    let mut _buf1: u32 = 0;
    let mut _buf2: u32 = 0;
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    unsafe {
        std::arch::asm!(
            include_str!("../../../tools/generate-verifier-asm/root_verifier.asm"),
            inout("x28") _input_ptr,
            inout("x29") _output_ptr,
            inout("x30") _buf1,
            inout("x31") _buf2,
        )
    }
}
