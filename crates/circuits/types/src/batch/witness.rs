use crate::{
    ProofCarryingWitness,
    chunk::ChunkInfo,
    proof::{ProgramCommitment, RootProofWithPublicValues},
};

use super::ReferenceHeader;

/// Witness to the batch circuit.
#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct BatchWitness {
    /// Flattened root proofs from all chunks in the batch.
    #[rkyv()]
    pub chunk_proofs: Vec<RootProofWithPublicValues>,
    /// Chunk infos.
    #[rkyv()]
    pub chunk_infos: Vec<ChunkInfo>,
    /// Blob bytes.
    #[rkyv()]
    pub blob_bytes: Vec<u8>,
    /// Header for reference.
    #[rkyv()]
    pub reference_header: ReferenceHeader,
}

impl ProofCarryingWitness for ArchivedBatchWitness {
    fn get_proofs(&self) -> Vec<RootProofWithPublicValues> {
        self.chunk_proofs
            .iter()
            .map(|archived| RootProofWithPublicValues {
                //flattened_proof: archived
                  //  .flattened_proof
                    //.iter()
                 //   .map(|u32_le| u32_le.to_native())
                //    .collect(),
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
