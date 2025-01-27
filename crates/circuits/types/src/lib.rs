use alloy_primitives::B256;
use proof::RootProofWithPublicValues;

pub mod batch;

pub mod chunk;

pub mod proof;

pub mod utils;

const CHUNK_SIZE: usize = 4;

/// Defines behaviour to be implemented by types representing the public-input values of a circuit.
pub trait PublicInputs {
    /// Keccak-256 digest of the public inputs. The public-input hash are revealed as public values
    /// via [`openvm::io::reveal`].
    fn pi_hash(&self) -> B256;

    /// Validation logic between public inputs of two contiguous instances.
    fn validate(&self, prev_pi: &Self);
}

impl PublicInputs for () {
    fn pi_hash(&self) -> B256 {
        unreachable!("PublicInputs::pi_hash for ()");
    }
    fn validate(&self, _prev_pi: &Self) {
        unreachable!("PublicInputs::validate for ()");
    }
}

/// Circuit defines the higher-level behaviour to be observed by a [`openvm`] guest program.
pub trait Circuit {
    /// The witness provided to the circuit.
    type Witness;

    /// The public-input values for the circuit.
    type PublicInputs: PublicInputs;

    /// The public-input values from the previous layer's circuit, that must be validated in the
    /// current circuit.
    type PrevPublicInputs: PublicInputs;

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
    /// Derive the public-input values of the previous layer's circuit from the current circuit's
    /// witness. Since the current possibly aggregates several of those proofs, we return a [`Vec`]
    /// of the previous circuit's public-input values.
    fn prev_public_inputs(witness: &Self::Witness) -> Vec<Self::PrevPublicInputs>;

    /// Verify the previous layer's circuit's proofs that are aggregated in the current circuit.
    ///
    /// Also returns the root proofs being aggregated.
    fn verify_proofs(witness: &Self::Witness) -> Vec<RootProofWithPublicValues>;

    /// Derive the previous circuit's public input hashes from the root proofs being aggregated.
    fn deserialize_prev_pi_hashes(proofs: &[RootProofWithPublicValues]) -> Vec<B256>;

    /// Validate that the previous public inputs in fact hash to the `pi_hash`es deserialized from the root proofs.
    fn validate_prev_pi(prev_pis: &[Self::PrevPublicInputs], prev_pi_hashes: &[B256]) {
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
