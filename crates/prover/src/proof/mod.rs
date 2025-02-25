use std::path::Path;

use openvm_native_recursion::halo2::EvmProof as OpenVmEvmProof;
use openvm_sdk::verifier::root::types::RootVmVerifierInput;
use openvm_stark_sdk::{openvm_stark_backend::proof::Proof, p3_baby_bear::BabyBear};
use sbv::primitives::B256;
use scroll_zkvm_circuit_input_types::{batch::BatchInfo, bundle::BundleInfo, chunk::ChunkInfo};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use snark_verifier_sdk::snark_verifier::{
    halo2_base::halo2_proofs::halo2curves::bn256::Fr, util::arithmetic::PrimeField,
};

use crate::{
    Error, SC,
    utils::{as_base64, base64 as vec_as_base64, short_git_version},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct EvmProof {
    #[serde(with = "vec_as_base64")]
    pub proof: Vec<u8>,
    #[serde(with = "vec_as_base64")]
    pub instances: Vec<u8>,
}

impl From<&OpenVmEvmProof> for EvmProof {
    fn from(value: &OpenVmEvmProof) -> Self {
        assert_eq!(
            value.instances.len(),
            1,
            "OpenVmEvmProof: Into<EvmProof>: expected 1 instance column"
        );

        let instances = value.instances[0]
            .iter()
            .flat_map(|fr| {
                let mut be_bytes = fr.to_bytes();
                be_bytes.reverse();
                be_bytes
            })
            .collect::<Vec<u8>>();

        Self {
            proof: value.proof.to_vec(),
            instances,
        }
    }
}

impl From<&EvmProof> for OpenVmEvmProof {
    fn from(value: &EvmProof) -> Self {
        assert_eq!(
            value.instances.len() % 32,
            0,
            "expect len(instances) % 32 == 0"
        );

        let instances = vec![
            value
                .instances
                .chunks_exact(32)
                .map(|be_bytes| {
                    Fr::from_repr({
                        let mut le_bytes: [u8; 32] = be_bytes
                            .try_into()
                            .expect("instances.len() % 32 == 0 has already been asserted");
                        le_bytes.reverse();
                        le_bytes
                    })
                    .expect("Fr::from_repr failed")
                })
                .collect::<Vec<Fr>>(),
        ];

        Self {
            proof: value.proof.to_vec(),
            instances,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "RootProof")]
struct RootProofDef {
    #[serde(with = "as_base64")]
    proofs: Vec<Proof<SC>>,
    #[serde(with = "as_base64")]
    public_values: Vec<BabyBear>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProofEnum {
    #[serde(with = "RootProofDef")]
    Root(RootProof),
    Evm(EvmProof),
}

impl From<RootProof> for ProofEnum {
    fn from(value: RootProof) -> Self {
        Self::Root(value)
    }
}

impl From<EvmProof> for ProofEnum {
    fn from(value: EvmProof) -> Self {
        Self::Evm(value)
    }
}

impl From<OpenVmEvmProof> for ProofEnum {
    fn from(value: OpenVmEvmProof) -> Self {
        Self::Evm(EvmProof::from(&value))
    }
}

impl ProofEnum {
    pub fn as_root_proof(&self) -> Option<&RootProof> {
        match self {
            Self::Root(proof) => Some(proof),
            _ => None,
        }
    }

    pub fn as_evm_proof(&self) -> Option<OpenVmEvmProof> {
        match self {
            Self::Evm(proof) => Some(OpenVmEvmProof::from(proof)),
            _ => None,
        }
    }

    pub fn into_root_proof(self) -> Option<RootProof> {
        match self {
            Self::Root(proof) => Some(proof),
            _ => None,
        }
    }

    pub fn into_evm_proof(self) -> Option<OpenVmEvmProof> {
        match self {
            Self::Evm(ref proof) => Some(OpenVmEvmProof::from(proof)),
            _ => None,
        }
    }
}

/// A wrapper around the actual inner proof.
#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedProof<Metadata> {
    /// Generic metadata carried by a proof.
    pub metadata: Metadata,
    /// The inner proof, either a [`RootProof`] or [`EvmProof`] depending on the [`crate::ProverType`].
    pub proof: ProofEnum,
    /// Represents the verifying key in serialized form. The purpose of including the verifying key
    /// along with the proof is to allow a verifier-only mode to identify the source of proof
    /// generation.
    ///
    /// For [`RootProof`] the verifying key is denoted by the digest of the VM's program.
    ///
    /// For [`EvmProof`] its the raw bytes of the halo2 circuit's `VerifyingKey`.
    ///
    /// We encode the vk in base64 format during JSON serialization.
    #[serde(with = "vec_as_base64", default)]
    pub vk: Vec<u8>,
    /// Represents the git ref for `zkvm-prover` that was used to construct the proof.
    ///
    /// This is useful for debugging.
    pub git_version: String,
}

/// Alias for convenience.
pub type RootProof = RootVmVerifierInput<SC>;

/// Alias for convenience.
pub type ChunkProof = WrappedProof<ChunkProofMetadata>;

/// Alias for convenience.
pub type BatchProof = WrappedProof<BatchProofMetadata>;

/// Alias for convenience.
pub type BundleProof = WrappedProof<BundleProofMetadata>;

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

impl<Metadata> WrappedProof<Metadata>
where
    Metadata: DeserializeOwned + Serialize,
{
    /// Wrap a proof with some metadata.
    pub fn new<P: Into<ProofEnum>>(metadata: Metadata, proof: P, vk: Option<&[u8]>) -> Self {
        Self {
            metadata,
            proof: proof.into(),
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

impl ChunkProof {
    pub fn as_proof(&self) -> &RootProof {
        self.proof
            .as_root_proof()
            .expect("ChunkProof contains RootProof")
    }
    pub fn into_proof(self) -> RootProof {
        self.proof
            .into_root_proof()
            .expect("ChunkProof contains RootProof")
    }
}

impl BatchProof {
    pub fn as_proof(&self) -> &RootProof {
        self.proof
            .as_root_proof()
            .expect("BatchProof contains RootProof")
    }
    pub fn into_proof(self) -> RootProof {
        self.proof
            .into_root_proof()
            .expect("BatchProof contains RootProof")
    }
}

impl BundleProof {
    pub fn as_proof(&self) -> OpenVmEvmProof {
        self.proof
            .as_evm_proof()
            .expect("BundleProof contains EvmProof")
    }
    pub fn into_proof(self) -> OpenVmEvmProof {
        self.proof
            .into_evm_proof()
            .expect("BundleProof contains EvmProof")
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use base64::{Engine, prelude::BASE64_STANDARD};
    use openvm_native_recursion::halo2::EvmProof;
    use scroll_zkvm_circuit_input_types::{PublicInputs, bundle::BundleInfo};
    use snark_verifier_sdk::snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::Fr;

    use super::{BatchProof, BundleProof, BundleProofMetadata, ChunkProof};

    #[test]
    fn test_roundtrip() -> eyre::Result<()> {
        macro_rules! assert_roundtrip {
            ($fd:expr, $proof:ident) => {
                let proof_str_expected =
                    std::fs::read_to_string(std::path::Path::new("./testdata").join($fd))?;
                let proof = serde_json::from_str::<$proof>(&proof_str_expected)?;
                let proof_str_got = serde_json::to_string(&proof)?;
                assert_eq!(proof_str_got, proof_str_expected);
            };
        }

        assert_roundtrip!("chunk-proof.json", ChunkProof);
        assert_roundtrip!("batch-proof.json", BatchProof);
        // assert_roundtrip!("bundle-proof.json", BundleProof);

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
            &serde_json::json!({
                "proof": proof_base64,
                "instances": instances_base64,
            }),
        );
        assert_eq!(
            bundle_proof_json.get("vk").unwrap(),
            &serde_json::Value::String(vk_base64),
        );

        let bundle_proof_de = serde_json::from_value::<BundleProof>(bundle_proof_json)?;

        assert_eq!(
            bundle_proof_de.as_proof().proof,
            bundle_proof.as_proof().proof
        );
        assert_eq!(
            bundle_proof_de.as_proof().instances,
            bundle_proof.as_proof().instances,
        );
        assert_eq!(bundle_proof_de.vk, bundle_proof.vk);

        Ok(())
    }
}
