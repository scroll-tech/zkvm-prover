use types_base::{
    aggregation::{AggregationInput, ProgramCommitment, ProofCarryingWitness},
    public_inputs::{ForkName, batch::BatchInfo, chunk::ChunkInfo},
};

use crate::{
    builder::{
        BatchInfoBuilder, BatchInfoBuilderV6, BatchInfoBuilderV7, BatchInfoBuilderV8,
        BuilderArgsV6, BuilderArgsV7, BuilderArgsV8,
    },
    header::{ArchivedReferenceHeader, ReferenceHeader},
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
    #[rkyv()]
    pub kzg_commitment_hint: [u8; 96],
    /// kzg proof
    #[rkyv()]
    pub kzg_proof: Bytes48,
    #[rkyv()]
    pub kzg_proof_hint: [u8; 96],
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
        println!("6000");
        let chunk_infos: Vec<ChunkInfo> = witness.chunk_infos.iter().map(|ci| ci.into()).collect();

        match &witness.reference_header {
            ArchivedReferenceHeader::V6(header) => {
                let args = BuilderArgsV6 {
                    header: header.into(),
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    kzg_commitment: None,
                    kzg_proof: None,
                    kzg_commitment_hint: None,
                    kzg_proof_hint: None,
                };
                BatchInfoBuilderV6::build(args)
            }
            ArchivedReferenceHeader::V7(header) => {
                let args = BuilderArgsV7 {
                    header: header.into(),
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    kzg_commitment: Some(witness.point_eval_witness.kzg_commitment),
                    kzg_proof: Some(witness.point_eval_witness.kzg_proof),
                    kzg_commitment_hint: Some(witness.point_eval_witness.kzg_commitment_hint),
                    kzg_proof_hint: Some(witness.point_eval_witness.kzg_proof_hint),
                };
                BatchInfoBuilderV7::build(args)
            }
            ArchivedReferenceHeader::V8(header) => {
                let args = BuilderArgsV8 {
                    header: header.into(),
                    chunk_infos,
                    blob_bytes: witness.blob_bytes.to_vec(),
                    kzg_commitment: Some(witness.point_eval_witness.kzg_commitment),
                    kzg_proof: Some(witness.point_eval_witness.kzg_proof),
                    kzg_commitment_hint: Some(witness.point_eval_witness.kzg_commitment_hint),
                    kzg_proof_hint: Some(witness.point_eval_witness.kzg_proof_hint),
                };

                println!("6001");
                BatchInfoBuilderV8::build(args)
            }
        }
    }
}
