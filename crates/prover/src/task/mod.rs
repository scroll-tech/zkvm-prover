use openvm_sdk::StdIn;
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
use scroll_zkvm_circuit_input_types::proof::{AggregationInput, ProgramCommitment};

use crate::proof::WrappedProof;

pub mod batch;

pub mod chunk;

pub mod bundle;

/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
pub trait ProvingTask: serde::de::DeserializeOwned {
    fn identifier(&self) -> String;

    fn build_guest_input(&self) -> Result<StdIn, rkyv::rancor::Error>;
}

/// Flatten a [`WrappedProof`] and split the proof from the public values. We also split out the
/// program commitments.
pub fn flatten_wrapped_proof<Metadata>(wrapped_proof: &WrappedProof<Metadata>) -> AggregationInput {
    let public_values = wrapped_proof
        .proof
        .as_root_proof()
        .expect("flatten_wrapped_proof expects RootProof")
        .public_values
        .iter()
        .map(|x| x.as_canonical_u32())
        .collect();
    let commitment = ProgramCommitment::deserialize(&wrapped_proof.vk);

    AggregationInput {
        public_values,
        commitment,
    }
}

#[cfg(test)]
mod tests {
    use sbv::primitives::types::BlockWitness;

    use crate::ChunkProof;

    use super::{batch::BatchProvingTask, flatten_wrapped_proof};

    #[test]
    fn read_proof_and_dbg_commitment() -> eyre::Result<()> {
        let proof_str =
            std::fs::read_to_string(std::path::Path::new("./testdata").join("chunk-proof.json"))?;
        let proof = serde_json::from_str::<ChunkProof>(&proof_str)?;
        let aggr_input = flatten_wrapped_proof(&proof);
        assert_eq!(
            aggr_input.commitment.exe,
            crate::commitments::chunk::EXE_COMMIT
        );
        assert_eq!(
            aggr_input.commitment.leaf,
            crate::commitments::chunk::LEAF_COMMIT
        );

        Ok(())
    }

    #[test]
    fn read_task_and_dbg_commitment() -> eyre::Result<()> {
        let task_str = std::fs::read_to_string(
            std::path::Path::new("./testdata").join("batch-task-panic.json"),
        )?;
        let task = serde_json::from_str::<BatchProvingTask>(&task_str)?;
        for chunk_proof in task.chunk_proofs.iter() {
            let aggr_input = flatten_wrapped_proof(chunk_proof);
            assert_eq!(
                aggr_input.commitment.exe,
                crate::commitments::chunk::EXE_COMMIT
            );
            assert_eq!(
                aggr_input.commitment.leaf,
                crate::commitments::chunk::LEAF_COMMIT
            );
        }

        Ok(())
    }

    #[test]
    fn read_block_witness() -> eyre::Result<()> {
        let witness_str =
            std::fs::read_to_string(std::path::Path::new("./testdata").join("2.json"))?;
        let witness = serde_json::from_str::<BlockWitness>(&witness_str)?;
        Ok(())
    }
}
