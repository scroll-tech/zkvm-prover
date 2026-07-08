pub mod io;
pub use io::read_witnesses;

use alloy_primitives::B256;
use itertools::Itertools;
use public_inputs::PublicInputs;
use scroll_zkvm_types_base as types_base;
pub use types_base::{
    aggregation::{AggregationInput, ProgramCommitment, ProofCarryingWitness},
    public_inputs, utils,
};

/// Reveal the public-input values as openvm public values.
pub fn reveal_pi_hash(pi_hash: B256) {
    openvm::io::println(format!("pi_hash = {pi_hash:?}"));
    openvm::io::reveal_bytes32(*pi_hash);
}

/// Circuit defines the higher-level behaviour to be observed by a [`openvm`] guest program.
pub trait Circuit {
    /// The witness provided to the circuit.
    type Witness;

    /// The public-input values for the circuit.
    type PublicInputs: PublicInputs;

    /// Reads bytes from openvm StdIn.
    fn read_witness_bytes() -> Vec<u8>;

    /// Deserialize raw bytes into the circuit's witness type.
    fn deserialize_witness(witness_bytes: &[u8]) -> Self::Witness;

    /// Validate the witness to produce the circuit's public inputs.
    fn validate(witness: Self::Witness) -> Self::PublicInputs;

    /// Reveal the public inputs.
    fn reveal_pi(pi: &Self::PublicInputs) {
        reveal_pi_hash(pi.pi_hash())
    }
}

#[allow(dead_code)]
const NUM_PUBLIC_VALUES: usize = 32;

/// Circuit that additional aggregates proofs from other [`Circuits`][Circuit].
pub trait AggCircuit: Circuit
where
    Self::Witness: ProofCarryingWitness,
{
    /// The public-input values of the proofs being aggregated.
    type AggregatedPublicInputs: PublicInputs;

    /// Check if the commitment in proof is valid (from program(s)
    /// we have expected)
    fn verify_commitments(commitment: &ProgramCommitment);

    /// Verify the proofs being aggregated.
    ///
    /// Also returns the root proofs being aggregated.
    fn verify_proofs(witness: &Self::Witness) -> Vec<AggregationInput> {
        let proofs = witness.get_proofs();

        #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
        {
            let input_commits: Vec<[u8; 32]> = openvm::io::read();
            assert_eq!(
                proofs.len(),
                input_commits.len(),
                "mismatch between proofs and input commits"
            );

            for (proof, input_commit) in proofs.iter().zip(input_commits.iter()) {
                Self::verify_commitments(&proof.commitment);
                verify_proof(&proof.commitment, proof.public_values.as_slice(), input_commit);
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
        {
            for proof in proofs.iter() {
                Self::verify_commitments(&proof.commitment);
                verify_proof(&proof.commitment, proof.public_values.as_slice(), &[0u8; 32]);
            }
        }

        proofs
    }

    /// Derive the public-input values of the proofs being aggregated from the witness.
    fn aggregated_public_inputs(witness: &Self::Witness) -> Vec<Self::AggregatedPublicInputs>;

    /// Derive the public-input hashes of the aggregated proofs from the proofs itself.
    fn aggregated_pi_hashes(proofs: &[AggregationInput]) -> Vec<B256>;

    /// Validate that the public-input values of the aggregated proofs are well-formed.
    ///
    /// - That the public-inputs of contiguous chunks/batches are valid
    /// - That the public-input values in fact hash to the pi_hash values from the root proofs.
    fn validate_aggregated_pi(agg_pis: &[Self::AggregatedPublicInputs], agg_pi_hashes: &[B256]) {
        // There should be at least a single proof being aggregated.
        assert!(!agg_pis.is_empty(), "at least 1 pi to aggregate");

        // Validation for the contiguous public-input values.
        for w in agg_pis.windows(2) {
            w[1].validate(&w[0]);
        }

        // Validation for public-input values hash being the pi_hash from root proof.
        for (agg_pi, &agg_pi_hash) in agg_pis.iter().zip_eq(agg_pi_hashes.iter()) {
            assert_eq!(
                agg_pi.pi_hash(),
                agg_pi_hash,
                "pi hash mismatch between proofs and witness computed"
            );
        }
    }
}

/// Convert a [u32; 8] commitment array to a 32-byte commit.
#[allow(dead_code)]
fn u32_array_to_commit(arr: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &w) in arr.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    bytes
}

/// Verify a root proof using deferred STARK verification (v2).
#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
fn verify_proof(commitment: &ProgramCommitment, public_inputs: &[u32], input_commit: &[u8; 32]) {
    use openvm_verify_stark_guest::{verify_stark, ProofOutput};

    // Sanity check for the number of public-input values.
    assert_eq!(public_inputs.len(), NUM_PUBLIC_VALUES);

    // OpenVM stores each user public value byte as a 32-bit field element; the
    // verify-stark guest helper collapses them back to dense bytes.
    let expected = ProofOutput {
        app_exe_commit: u32_array_to_commit(&commitment.exe),
        app_vm_commit: u32_array_to_commit(&commitment.vm),
        user_public_values: public_inputs.iter().map(|&w| w as u8).collect(),
    };

    verify_stark::<0>(input_commit, &expected);
}

#[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
fn verify_proof(
    _commitment: &ProgramCommitment,
    _public_inputs: &[u32],
    _input_commit: &[u8; 32],
) {
    // This function is guest-only: the actual deferred STARK verification happens inside
    // the zkvm guest via `openvm_verify_stark_guest::verify_stark`. Calling it on a non-zkvm
    // target is a programming error.
    unimplemented!("verify_proof should only be called on zkvm target")
}

/// This macro is used to manually drop an expression on zkvm (non x86/aarch64 targets).
#[macro_export]
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
macro_rules! manually_drop_on_zkvm {
    ($e:expr) => {
        std::mem::ManuallyDrop::new($e)
    };
}

/// This macro is used to manually drop an expression on zkvm (non x86/aarch64 targets).
#[macro_export]
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! manually_drop_on_zkvm {
    ($e:expr) => {
        $e
    };
}
