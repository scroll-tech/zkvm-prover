use crate::utils::{as_base64, vec_as_base64};
use openvm_native_recursion::halo2::RawEvmProof;
use openvm_sdk::SC;
use openvm_stark_sdk::{
    openvm_stark_backend::{p3_field::PrimeField32, proof::Proof},
    p3_baby_bear::BabyBear,
};
use serde::{Deserialize, Serialize};

/// Helper type for convenience that implements [`From`] and [`Into`] traits between
/// [`OpenVmEvmProof`]. The difference is that the instances in [`EvmProof`] are the byte-encoding
/// of the flattened [`Fr`] elements.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct EvmProof {
    /// The proof bytes.
    #[serde(with = "vec_as_base64")]
    pub proof: Vec<u8>,
    /// Byte-encoding of the flattened scalar fields representing the public inputs of the SNARK
    /// proof.
    #[serde(with = "vec_as_base64")]
    pub instances: Vec<u8>,
    /*
    //pub accumulator: Vec<u8>,
    /// The public inputs of the SNARK proof.
    /// Previously the `instance`s are U256 values, with accumulator and digests.
    /// For real user PI values, they will be like 0x0000..00000ab, only 1 byte non zero.
    /// Usually of length (12+2+32)x32
    /// Now: the `instance` is splitted. The `user_public_values` is "dense".
    /// Each byte is valid PI. Usually of length 32.
    //#[serde(with = "vec_as_base64")]
    //pub user_public_values: Vec<u8>,
    //pub digest1: [u32; 8],
    //pub digest2: [u32; 8],
     */
}

/// Helper to modify serde implementations on the remote [`RootProof`] type.
#[derive(Clone, Serialize, Deserialize)]
pub struct StarkProof {
    /// The proofs. The length is always 1
    /// Vec is used for old data compatibility.
    #[serde(with = "as_base64")]
    pub proofs: Vec<Proof<SC>>,
    /// The public values for the proof.
    #[serde(with = "as_base64")]
    pub public_values: Vec<BabyBear>,
    //pub exe_commitment: [u32; 8],
    //pub vm_commitment: [u32; 8],
}

pub use openvm_sdk::types::EvmProof as OpenVmEvmProof;
use snark_verifier_sdk::snark_verifier::{
    halo2_base::halo2_proofs::halo2curves::bn256::Fr, util::arithmetic::PrimeField,
};

impl From<OpenVmEvmProof> for EvmProof {
    fn from(value: OpenVmEvmProof) -> Self {
        let raw_proof: RawEvmProof = value.try_into().expect("fail to convert");
        let instances = raw_proof
            .instances
            .iter()
            .flat_map(|fr| {
                let mut be_bytes = fr.to_bytes();
                be_bytes.reverse();
                be_bytes
            })
            .collect::<Vec<u8>>();
        Self {
            proof: raw_proof.proof,
            instances,
        }
    }
}

impl From<EvmProof> for OpenVmEvmProof {
    fn from(value: EvmProof) -> Self {
        assert_eq!(
            value.instances.len() % 32,
            0,
            "expect len(instances) % 32 == 0"
        );

        let instances = value
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
            .collect::<Vec<Fr>>();
        let raw_proof = RawEvmProof {
            instances,
            proof: value.proof,
        };
        raw_proof.try_into().expect("fail to convert")
    }
}

/// Lists the proof variants possible in Scroll's proving architecture.
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProofEnum {
    /// Represents a STARK proof used for intermediary layers, i.e. chunk and batch.
    Stark(StarkProof),
    /// Represents a SNARK proof used for the final layer to be verified on-chain, i.e. bundle.
    Evm(EvmProof),
}

impl From<StarkProof> for ProofEnum {
    fn from(value: StarkProof) -> Self {
        Self::Stark(value)
    }
}

impl From<EvmProof> for ProofEnum {
    fn from(value: EvmProof) -> Self {
        Self::Evm(value)
    }
}

impl ProofEnum {
    /// Get the stark proof as reference.
    pub fn as_stark_proof(&self) -> Option<&StarkProof> {
        match self {
            Self::Stark(proof) => Some(proof),
            _ => None,
        }
    }

    /// Get the EVM proof as defined in [`openvm_native_recursion`].
    ///
    /// Essentially construct a [`OpenVmEvmProof`] from the inner contained [`EvmProof`].
    pub fn as_evm_proof(&self) -> Option<&EvmProof> {
        match self {
            Self::Evm(proof) => Some(proof),
            _ => None,
        }
    }

    /// Consumes the proof enum and returns the contained root proof.
    pub fn into_stark_proof(self) -> Option<StarkProof> {
        match self {
            Self::Stark(proof) => Some(proof),
            _ => None,
        }
    }

    /// Consumes the proof enum and returns the [`OpenVmEvmProof`].
    pub fn into_evm_proof(self) -> Option<EvmProof> {
        match self {
            Self::Evm(proof) => Some(proof),
            _ => None,
        }
    }

    /// Derive public inputs from the proof.
    pub fn public_values(&self) -> Vec<u32> {
        match self {
            Self::Stark(stark_proof) => stark_proof
                .public_values
                .iter()
                .map(|x| x.as_canonical_u32())
                .collect::<Vec<u32>>(),
            Self::Evm(evm_proof) => {
                // The first 12 scalars are accumulators.
                // The next 2 scalars are digests.
                // The next 32 scalars are the public input hash.
                let pi_hash_bytes = evm_proof
                    .instances
                    .iter()
                    .skip(14 * 32)
                    .take(32 * 32)
                    .cloned()
                    .collect::<Vec<u8>>();

                // The 32 scalars of public input hash actually only have the LSB that is the
                // meaningful byte.
                pi_hash_bytes
                    .chunks_exact(32)
                    .map(|bytes32_chunk| bytes32_chunk[31] as u32)
                    .collect::<Vec<u32>>()
            }
        }
    }
}
