use crate::{
    builder::*,
    header::{ArchivedReferenceHeader, ReferenceHeader},
};

use types_base::{
    aggregation::{AggregationInput, ProgramCommitment, ProofCarryingWitness},
    public_inputs::{ForkName, batch::BatchInfo, chunk::ChunkInfo},
};

/// Simply rewrap byte48 to avoid unnecessary dep
pub type Bytes48 = [u8; 48];

/// Witness required by applying point evaluation
#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct PointEvalWitness {
    /// kzg commitment
    #[rkyv()]
    pub kzg_commitment: Bytes48,
    /// kzg proof
    #[rkyv()]
    pub kzg_proof: Bytes48,
}

/// Witness to the batch circuit.
#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
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

impl ProofCarryingWitness for ArchivedBatchWitness {
    fn get_proofs(&self) -> Vec<AggregationInput> {
        self.chunk_proofs
            .iter()
            .map(|archived| AggregationInput {
                public_values: archived
                    .public_values
                    .iter()
                    .map(|u32_le| u32_le.to_native())
                    .collect(),
                commitment: ProgramCommitment::from(&archived.commitment),
            })
            .collect()
    }
}

impl From<&ArchivedBatchWitness> for BatchInfo {
    fn from(witness: &ArchivedBatchWitness) -> Self {
        match &witness.reference_header {
            ArchivedReferenceHeader::V6(header) => {
                let chunk_infos: Vec<ChunkInfo> =
                    witness.chunk_infos.iter().map(|ci| ci.into()).collect();
                BatchInfoBuilderV6::build(&header.into(), &chunk_infos, &witness.blob_bytes)
            }
            ArchivedReferenceHeader::V7(header) => BatchInfoBuilderV7::build(
                &header.into(),
                &witness.chunk_infos,
                &witness.blob_bytes,
                &witness.point_eval_witness.kzg_commitment,
                &witness.point_eval_witness.kzg_proof,
            ),
        }
    }
}
