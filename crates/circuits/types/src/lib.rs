use alloy_primitives::B256;

use crate::proof::RootProofWithPublicValues;

pub mod batch;

pub mod bundle;

pub mod chunk;

pub mod proof;

pub mod utils;

/// The number of bytes (`u8`) chunked together before revealing as openvm public-inputs. Since the
/// revealed value supported by openvm is `u32`, we chunk `[u8; 4]` together in little-endian order.
const CHUNK_SIZE: usize = 4;

/// Defines behaviour to be implemented by types representing the public-input values of a circuit.
pub trait PublicInputs {
    /// Keccak-256 digest of the public inputs. The public-input hash are revealed as public values
    /// via [`openvm::io::reveal`].
    fn pi_hash(&self) -> B256;

    /// Validation logic between public inputs of two contiguous instances.
    fn validate(&self, prev_pi: &Self);
}

/// Circuit defines the higher-level behaviour to be observed by a [`openvm`] guest program.
pub trait Circuit {
    /// The witness provided to the circuit.
    type Witness;

    /// The public-input values for the circuit.
    type PublicInputs: PublicInputs;

    /// Setup openvm extensions as a preliminary step.
    fn setup();

    /// Reads bytes from openvm StdIn.
    fn read_witness_bytes() -> Vec<u8>;

    /// Deserialize raw bytes into the circuit's witness type.
    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness;

    /// Validate the witness to produce the circuit's public inputs.
    fn validate(witness: &Self::Witness) -> Self::PublicInputs;

    /// Reveal the public inputs.
    fn reveal_pi(pi: &Self::PublicInputs) {
        for (i, part) in pi.pi_hash().chunks_exact(CHUNK_SIZE).enumerate() {
            let value = u32::from_le_bytes(part.try_into().unwrap());
            openvm::io::print(format!("pi[{i}] = {value:?}"));
            openvm::io::reveal(value, i)
        }
    }
}

/// Circuit that additional aggregates proofs from other [`Circuits`][Circuit].
pub trait AggCircuit: Circuit
where
    Self::Witness: ProofCarryingWitness,
{
    /// The public-input values of the proofs being aggregated.
    type AggregatedPublicInputs: PublicInputs;

    /// Verify the previous layer's circuit's proofs that are aggregated in the current circuit.
    ///
    /// Also returns the root proofs being aggregated.
    fn verify_proofs(witness: &Self::Witness) -> Vec<RootProofWithPublicValues> {
        let prev_proofs = witness.get_proofs();

        for proof in prev_proofs.iter() {
            proof::verify_proof(
                proof.flattened_proof.as_slice(),
                proof.public_values.as_slice(),
            );
        }

        prev_proofs
    }

    /// Derive the public-input values of the previous layer's circuit from the current circuit's
    /// witness. Since the current possibly aggregates several of those proofs, we return a [`Vec`]
    /// of the previous circuit's public-input values.
    fn prev_public_inputs(witness: &Self::Witness) -> Vec<Self::AggregatedPublicInputs>;

    /// Derive the previous circuit's public input hashes from the root proofs being aggregated.
    fn derive_prev_pi_hashes(proofs: &[RootProofWithPublicValues]) -> Vec<B256>;

    /// Validate the previous circuit layer's public-input values.
    ///
    /// - That the public-inputs of contiguous chunks/batches are valid
    /// - That the public-input values in fact hash to the pi_hash values from the root proofs.
    fn validate_prev_pi(prev_pis: &[Self::AggregatedPublicInputs], prev_pi_hashes: &[B256]) {
        // Validation for the contiguous public-input values.
        for w in prev_pis.windows(2) {
            w[1].validate(&w[0]);
        }

        // Validation for public-input values hash being the pi_hash from root proof.
        for (prev_pi, &prev_pi_hash) in prev_pis.iter().zip(prev_pi_hashes.iter()) {
            assert_eq!(
                prev_pi.pi_hash(),
                prev_pi_hash,
                "pi hash mismatch between proofs and witness computed"
            );
        }
    }
}

/// Witness for an [`AggregationCircuit`][AggCircuit] that also carries proofs that are being
/// aggregated.
pub trait ProofCarryingWitness {
    /// Get the root proofs from the witness.
    fn get_proofs(&self) -> Vec<RootProofWithPublicValues>;
}
