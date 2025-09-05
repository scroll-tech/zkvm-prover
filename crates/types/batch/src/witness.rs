use halo2curves_axiom::CurveAffine;
use types_base::{
    aggregation::{AggregationInput, ProofCarryingWitness},
    public_inputs::{
        ForkName,
        batch::BatchInfo,
        chunk::{ChunkInfo, LegacyChunkInfo},
    },
};

use crate::{
    builder::{
        BatchInfoBuilder, BatchInfoBuilderV6, BatchInfoBuilderV7, BatchInfoBuilderV8,
        BuilderArgsV6, BuilderArgsV7, BuilderArgsV8,
        validium::{ValidiumBatchInfoBuilder, ValidiumBuilderArgs},
    },
    header::ReferenceHeader,
};

/// Simply rewrap byte48 to avoid unnecessary dep
pub type Bytes48 = [u8; 48];
mod array48 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(array: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(array)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = serde::Deserialize::deserialize(deserializer)?;
        bytes.try_into().map_err(|_| {
            let msg = format!("expected a byte array of length 48 but got {}", bytes.len());
            serde::de::Error::custom(msg)
        })
    }
}

/// Witness required by applying point evaluation
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PointEvalWitness {
    #[serde(with = "array48")]
    pub kzg_commitment_x: Bytes48,
    #[serde(with = "array48")]
    pub kzg_commitment_y: Bytes48,
    #[serde(with = "array48")]
    pub kzg_proof_x: Bytes48,
    #[serde(with = "array48")]
    pub kzg_proof_y: Bytes48,
}

/// Witness required by applying point evaluation
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
pub struct LegacyPointEvalWitness {
    /// kzg commitment
    #[rkyv()]
    #[serde(with = "array48")]
    pub kzg_commitment: Bytes48,
    /// kzg proof
    #[rkyv()]
    #[serde(with = "array48")]
    pub kzg_proof: Bytes48,
}

pub fn build_point_eval_witness(kzg_commitment: Bytes48, kzg_proof: Bytes48) -> PointEvalWitness {
    PointEvalWitness {
        kzg_commitment,
        kzg_proof,
    }
}

/// Witness to the batch circuit.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct BatchWitness {
    /// The version byte as per [version][types_base::version].
    pub version: u8,
    /// Flattened root proofs from all chunks in the batch.
    pub chunk_proofs: Vec<AggregationInput>,
    /// Chunk infos.
    pub chunk_infos: Vec<ChunkInfo>,
    /// Blob bytes.
    pub blob_bytes: Vec<u8>,
    /// Witness for point evaluation.
    ///
    /// Optional field as some domains (for eg. Validium) may not utilise EIP-4844 for DA,
    /// in case of which there is no point-eval witness.
    pub point_eval_witness: Option<PointEvalWitness>,
    /// Header for reference.
    pub reference_header: ReferenceHeader,
    /// The code version specify the chain spec
    pub fork_name: ForkName,
}

) -> Option<openvm_pairing::bls12_381::G1Affine> {
    use openvm_algebra_guest::IntMod;
    use openvm_ecc_guest::weierstrass::WeierstrassPoint;
    use openvm_pairing::bls12_381::{Fp, G1Affine};
    let x = Fp::from_be_bytes(&x)?;
    let y = Fp::from_be_bytes(&y)?;
    G1Affine::from_xy(x, y)
}

pub fn build_point(x: Bytes48, y: Bytes48) -> Option<halo2curves_axiom::bls12_381::G1Affine> {
    use halo2curves_axiom::bls12_381::{Fq, G1Affine};
    let x = Fq::from_bytes_be(&x).into_option()?;
    let y = Fq::from_bytes_be(&y).into_option()?;
    G1Affine::from_xy(x, y).into_option()
}

/// Witness to the batch circuit.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct BatchWitness {
    /// Flattened root proofs from all chunks in the batch.
    pub chunk_proofs: Vec<AggregationInput>,
    /// Chunk infos.
    pub chunk_infos: Vec<ChunkInfo>,
    /// Blob bytes.
    pub blob_bytes: Vec<u8>,
    /// Witness for point evaluation.
    ///
    /// Optional field as some domains (for eg. Validium) may not utilise EIP-4844 for DA,
    /// in case of which there is no point-eval witness.
    pub point_eval_witness: Option<PointEvalWitness>,
    /// Header for reference.
    pub reference_header: ReferenceHeader,
    /// The code version specify the chain spec
    pub fork_name: ForkName,
}

/// Witness to the batch circuit.
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
pub struct LegacyBatchWitness {
    /// Flattened root proofs from all chunks in the batch.
    #[rkyv()]
    pub chunk_proofs: Vec<AggregationInput>,
    /// Chunk infos.
    #[rkyv()]
    pub chunk_infos: Vec<LegacyChunkInfo>,
    /// Blob bytes.
    #[rkyv()]
    pub blob_bytes: Vec<u8>,
    /// Witness for point evaluation
    #[rkyv()]
    pub point_eval_witness: LegacyPointEvalWitness,
    /// Header for reference.
    #[rkyv()]
    pub reference_header: ReferenceHeader,
    /// The code version specify the chain spec
    #[rkyv()]
    pub fork_name: ForkName,
}

impl From<BatchWitness> for LegacyBatchWitness {
    fn from(value: BatchWitness) -> Self {
        let point_eval_witness = value.point_eval_witness.expect("should not be none");
        Self {
            chunk_proofs: value.chunk_proofs,
            chunk_infos: value.chunk_infos.into_iter().map(|c| c.into()).collect(),
            blob_bytes: value.blob_bytes,
            point_eval_witness: point_eval_witness.clone().into(),
            reference_header: value.reference_header,
            fork_name: value.fork_name,
        }
    }
}

impl ProofCarryingWitness for BatchWitness {
    fn get_proofs(&self) -> Vec<AggregationInput> {
        self.chunk_proofs.clone()
    }
}

impl From<&BatchWitness> for BatchInfo {
    fn from(witness: &BatchWitness) -> Self {
        let chunk_infos = witness.chunk_infos.to_vec();

        match &witness.reference_header {
            ReferenceHeader::V6(header) => {
                let args = BuilderArgsV6 {
                    header: *header,
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    point_eval_witness: None,
                };
                BatchInfoBuilderV6::build(args)
            }
            ReferenceHeader::V7(header) => {
                let point_eval_witness = witness
                    .point_eval_witness
                    .as_ref()
                    .expect("point_eval_witness missing for header::v7");
                let args = BuilderArgsV7 {
                    header: *header,
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    point_eval_witness: Some(point_eval_witness.clone()),
                };
                BatchInfoBuilderV7::build(args)
            }
            ReferenceHeader::V8(header) => {
                let point_eval_witness = witness
                    .point_eval_witness
                    .as_ref()
                    .expect("point_eval_witness missing for header::v8");
                let args = BuilderArgsV8 {
                    header: *header,
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    point_eval_witness: Some(point_eval_witness.clone()),
                };
                BatchInfoBuilderV8::build(args)
            }
            ReferenceHeader::Validium(header) => ValidiumBatchInfoBuilder::build(
                ValidiumBuilderArgs::new(*header, chunk_infos, witness.blob_bytes.to_vec()),
            ),
        }
    }
}
