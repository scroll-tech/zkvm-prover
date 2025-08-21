use types_base::{
    aggregation::{AggregationInput, ProgramCommitment, ProofCarryingWitness},
    public_inputs::{ForkName, batch::BatchInfo, chunk::ChunkInfo},
};

use crate::{
    builder::{
        BatchInfoBuilder, BatchInfoBuilderV6, BatchInfoBuilderV7, BatchInfoBuilderV8,
        BuilderArgsV6, BuilderArgsV7, BuilderArgsV8,
    },
    header::ReferenceHeader,
};

/// Simply rewrap byte48 to avoid unnecessary dep
pub type Bytes48 = [u8; 48];
mod array48 {
    use serde::{Deserialize, Deserializer, Serializer};

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
pub struct PointEvalWitness {
    /// kzg commitment
    #[rkyv()]
    #[serde(with = "array48")]
    pub kzg_commitment: Bytes48,
    /// kzg proof
    #[rkyv()]
    #[serde(with = "array48")]
    pub kzg_proof: Bytes48,
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
pub struct BatchWitness {
    /// Flattened root proofs from all chunks in the batch.
    #[rkyv()]
    pub chunk_proofs: Vec<AggregationInput>,
    /// Chunk infos.
    #[rkyv()]
    pub chunk_infos: Vec<ChunkInfo>,
    /// Blob bytes.
    #[rkyv()]
    pub blob_bytes: Vec<u8>,
    /// Witness for point evaluation
    pub point_eval_witness: PointEvalWitness,
    /// Header for reference.
    #[rkyv()]
    pub reference_header: ReferenceHeader,
    /// The code version specify the chain spec
    #[rkyv()]
    pub fork_name: ForkName,
}

impl ProofCarryingWitness for BatchWitness {
    fn get_proofs(&self) -> Vec<AggregationInput> {
        self.chunk_proofs.clone()
    }
}

impl From<&BatchWitness> for BatchInfo {
    fn from(witness: &BatchWitness) -> Self {
        let chunk_infos: Vec<ChunkInfo> = witness.chunk_infos.iter().map(|ci| ci.clone()).collect();

        match &witness.reference_header {
            ReferenceHeader::V6(header) => {
                let args = BuilderArgsV6 {
                    header: header.clone(),
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    kzg_commitment: None,
                    kzg_proof: None,
                };
                BatchInfoBuilderV6::build(args)
            }
            ReferenceHeader::V7(header) => {
                let args = BuilderArgsV7 {
                    header: header.clone(),
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    kzg_commitment: Some(witness.point_eval_witness.kzg_commitment),
                    kzg_proof: Some(witness.point_eval_witness.kzg_proof),
                };
                BatchInfoBuilderV7::build(args)
            }
            ReferenceHeader::V8(header) => {
                let args = BuilderArgsV8 {
                    header: header.clone(),
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    kzg_commitment: Some(witness.point_eval_witness.kzg_commitment),
                    kzg_proof: Some(witness.point_eval_witness.kzg_proof),
                };
                BatchInfoBuilderV8::build(args)
            }
        }
    }
}
