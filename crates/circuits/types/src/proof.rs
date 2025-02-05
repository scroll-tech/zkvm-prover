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
    /// Represent the commitment needed to verify a root proof
    pub program_commit: [[u32; 8]; 2],
}

/// Represent the commitment needed to verify a root proof
#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct ProgramCommit {
    /// The commitment to the root verifier's exe.
    pub exe: [u32; 8],
    /// The commitment to the root verifier's leaf.
    pub leaf: [u32; 8],
}

impl ProgramCommit {
    pub fn deserialize(commit_bytes: &[u8]) -> Self {
        let archived_data =
            rkyv::access::<ArchivedProgramCommit, rkyv::rancor::BoxedError>(commit_bytes).unwrap();
        Self {
            exe: archived_data.exe.map(|u32_le| u32_le.to_native()),
            leaf: archived_data.leaf.map(|u32_le| u32_le.to_native()),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::BoxedError>(self)
            .map(|v| v.to_vec())
            .unwrap()
    }
}

/// Number of public-input values, i.e. [u32; N].
///
/// Note that the actual value for each u32 is a byte.
const NUM_PUBLIC_VALUES: usize = 32;

/// Verify a root proof.
pub fn verify_proof(
    program_commitments: [[u32; 8]; 2],
    flattened_proof: &[u32],
    public_inputs: &[u32],
) {
    // Sanity check for the number of public-input values.
    assert_eq!(public_inputs.len(), NUM_PUBLIC_VALUES);

    // Extend the public-input values by prepending the commitments to the root verifier's exe and
    // leaf.
    let mut extended_public_inputs = vec![];
    extended_public_inputs.extend(program_commitments[0]);
    extended_public_inputs.extend(program_commitments[1]);
    extended_public_inputs.extend_from_slice(public_inputs);

    println!("verify proof with pi: {:?}", extended_public_inputs);
    // Pass through kernel and verify against root verifier's ASM.
    exec_kernel(flattened_proof, &extended_public_inputs);
    println!("verify proof done");
}

fn exec_kernel(input: &[u32], output: &[u32]) {
    let mut _input_ptr: *const u32 = input.as_ptr();
    let mut _output_ptr: *const u32 = output.as_ptr();
    let mut _buf1: u32 = 0;
    let mut _buf2: u32 = 0;
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    unsafe {
        std::arch::asm!(
            include_str!("../../../build-guest/root_verifier.asm"),
            inout("x28") _input_ptr,
            inout("x29") _output_ptr,
            inout("x30") _buf1,
            inout("x31") _buf2,
        )
    }
}
