use std::path::Path;

use openvm_native_recursion::halo2::EvmProof;
use openvm_sdk::verifier::root::types::RootVmVerifierInput;
use sbv::primitives::B256;
use scroll_zkvm_circuit_input_types::{batch::BatchInfo, bundle::BundleInfo, chunk::ChunkInfo};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{Error, SC, utils::short_git_version};

mod utils;
use utils::LegacyProofFormat;

/// A wrapper around the actual inner proof.
#[derive(Clone)]
pub struct WrappedProof<Metadata, Proof> {
    /// Generic metadata carried by a proof.
    pub metadata: Metadata,
    /// The inner proof, either a [`RootProof`] or [`EvmProof`] depending on the [`crate::ProverType`].
    pub proof: Proof,
    /// Represents the verifying key in serialized form. The purpose of including the verifying key
    /// along with the proof is to allow a verifier-only mode to identify the source of proof
    /// generation.
    ///
    /// For [`RootProof`] the verifying key is denoted by the digest of the VM's program.
    ///
    /// For [`EvmProof`] its the raw bytes of the halo2 circuit's `VerifyingKey`.
    ///
    /// We encode the vk in base64 format during JSON serialization.
    pub vk: Vec<u8>,
    /// Represents the git ref for `zkvm-prover` that was used to construct the proof.
    ///
    /// This is useful for debugging.
    pub git_version: String,
}

/// Alias for convenience.
pub type RootProof = RootVmVerifierInput<SC>;

/// Alias for convenience.
pub type ChunkProof = WrappedProof<ChunkProofMetadata, RootProof>;

/// Alias for convenience.
pub type BatchProof = WrappedProof<BatchProofMetadata, RootProof>;

/// Alias for convenience.
pub type BundleProof = WrappedProof<BundleProofMetadata, EvmProof>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkProofMetadata {
    pub chunk_info: ChunkInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchProofMetadata {
    pub batch_info: BatchInfo,
    pub batch_hash: B256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleProofMetadata {
    pub bundle_info: BundleInfo,
    pub bundle_pi_hash: B256,
}

impl<Metadata, Proof> WrappedProof<Metadata, Proof>
where
    Metadata: DeserializeOwned + Serialize,
    Proof: DeserializeOwned + Serialize + LegacyProofFormat,
{
    /// Wrap a proof with some metadata.
    pub fn new(metadata: Metadata, proof: Proof, vk: Option<&[u8]>) -> Self {
        Self {
            metadata,
            proof,
            vk: vk.map(Vec::from).unwrap_or_default(),
            git_version: short_git_version(),
        }
    }

    /// Read and deserialize the proof.
    pub fn from_json<P: AsRef<Path>>(path_proof: P) -> Result<Self, Error> {
        crate::utils::read_json_deep(path_proof)
    }

    /// Serialize the proof and dumping at the given path.
    pub fn dump<P: AsRef<Path>>(&self, path_proof: P) -> Result<(), Error> {
        crate::utils::write_json(path_proof, &self)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use base64::{Engine, prelude::BASE64_STANDARD};
    use openvm_native_recursion::halo2::EvmProof;
    use scroll_zkvm_circuit_input_types::{PublicInputs, bundle::BundleInfo};
    use snark_verifier_sdk::snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::Fr;

    use super::{BundleProof, BundleProofMetadata, ChunkProof};

    #[test]
    fn test_serde_roundtrip() -> eyre::Result<()> {
        let proof_file = std::fs::File::open("./testdata/chunk-12508460-12508463.json")?;
        let proof = serde_json::from_reader::<_, ChunkProof>(proof_file)?;
        serde_json::to_string(&proof)?;

        Ok(())
    }

    #[test]
    fn test_dummy_proof() -> eyre::Result<()> {
        // 1. Metadata
        let metadata = {
            let bundle_info = BundleInfo {
                chain_id: 12345,
                num_batches: 12,
                prev_state_root: B256::repeat_byte(1),
                prev_batch_hash: B256::repeat_byte(2),
                post_state_root: B256::repeat_byte(3),
                batch_hash: B256::repeat_byte(4),
                withdraw_root: B256::repeat_byte(5),
            };
            let bundle_pi_hash = bundle_info.pi_hash();
            BundleProofMetadata {
                bundle_info,
                bundle_pi_hash,
            }
        };

        // 2. Proof
        let (proof, proof_base64) = {
            let proof = std::iter::empty()
                .chain(std::iter::repeat(1).take(1))
                .chain(std::iter::repeat(2).take(2))
                .chain(std::iter::repeat(3).take(3))
                .chain(std::iter::repeat(4).take(4))
                .chain(std::iter::repeat(5).take(5))
                .chain(std::iter::repeat(6).take(6))
                .chain(std::iter::repeat(7).take(7))
                .chain(std::iter::repeat(8).take(8))
                .chain(std::iter::repeat(9).take(9))
                .collect::<Vec<u8>>();
            let proof_base64 = BASE64_STANDARD.encode(&proof);
            (proof, proof_base64)
        };

        // 3. Instances
        let (instances, instances_base64) = {
            let instances = vec![vec![
                Fr::from(0x123456),   // LE: [0x56, 0x34, 0x12, 0x00, 0x00, ..., 0x00]
                Fr::from(0x98765432), // LE: [0x32, 0x54, 0x76, 0x98, 0x00, ..., 0x00]
            ]];
            let instances_flattened = std::iter::empty()
                .chain(std::iter::repeat(0x00).take(29))
                .chain(std::iter::once(0x12))
                .chain(std::iter::once(0x34))
                .chain(std::iter::once(0x56))
                .chain(std::iter::repeat(0x00).take(28))
                .chain(std::iter::once(0x98))
                .chain(std::iter::once(0x76))
                .chain(std::iter::once(0x54))
                .chain(std::iter::once(0x32))
                .collect::<Vec<u8>>();
            let instances_base64 = BASE64_STANDARD.encode(&instances_flattened);
            (instances, instances_base64)
        };

        // 4. VK
        let (vk, vk_base64) = {
            let vk = std::iter::empty()
                .chain(std::iter::repeat(1).take(9))
                .chain(std::iter::repeat(2).take(8))
                .chain(std::iter::repeat(3).take(7))
                .chain(std::iter::repeat(4).take(6))
                .chain(std::iter::repeat(5).take(5))
                .chain(std::iter::repeat(6).take(4))
                .chain(std::iter::repeat(7).take(3))
                .chain(std::iter::repeat(8).take(2))
                .chain(std::iter::repeat(9).take(1))
                .collect::<Vec<u8>>();
            let vk_base64 = BASE64_STANDARD.encode(&vk);
            (vk, vk_base64)
        };

        let evm_proof = EvmProof { instances, proof };
        let bundle_proof = BundleProof::new(metadata, evm_proof, Some(vk.as_slice()));
        let bundle_proof_json = serde_json::to_value(&bundle_proof)?;

        assert_eq!(
            bundle_proof_json.get("proof").unwrap(),
            &serde_json::Value::String(proof_base64),
        );
        assert_eq!(
            bundle_proof_json.get("instances").unwrap(),
            &serde_json::Value::String(instances_base64),
        );
        assert_eq!(
            bundle_proof_json.get("vk").unwrap(),
            &serde_json::Value::String(vk_base64),
        );

        let bundle_proof_de = serde_json::from_value::<BundleProof>(bundle_proof_json)?;

        assert_eq!(bundle_proof_de.proof.proof, bundle_proof.proof.proof);
        assert_eq!(
            bundle_proof_de.proof.instances,
            bundle_proof.proof.instances
        );
        assert_eq!(bundle_proof_de.vk, bundle_proof.vk);

        Ok(())
    }
}
