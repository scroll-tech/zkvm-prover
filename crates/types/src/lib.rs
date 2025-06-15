// re-export for a compatible interface with old circuit/types for prover

pub mod bundle {
    pub use types_base::public_inputs::bundle::{BundleInfo, BundleInfoV1, BundleInfoV2};
    pub use types_bundle::*;
}

pub mod batch {
    pub use types_base::public_inputs::batch::{ArchivedBatchInfo, BatchInfo, VersionedBatchInfo};
    pub use types_batch::*;
}

pub mod chunk {
    pub use types_base::public_inputs::chunk::{
        ArchivedChunkInfo, BlockContextV2, ChunkInfo, SIZE_BLOCK_CTX, VersionedChunkInfo,
    };
    use types_chunk::execute as chunk_execute;
    pub use types_chunk::*;

    /// overwrite the execute into a version with non-archieved argument (calling in non circuit
    /// environment never need archieved arguments)
    pub fn execute(witness: &ChunkWitness) -> Result<ChunkInfo, String> {
        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(witness)
            .map_err(|e| format!("failed to serialize chunk witness: {e}"))?;
        let chunk_witness =
            rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(&serialized)
                .map_err(|e| format!("rkyv deserialisation of chunk witness bytes failed: {e}"))?;
        chunk_execute(chunk_witness)
    }
}

pub use types_base::{aggregation as types_agg, public_inputs, utils};

pub mod proof;

pub mod task;
pub use task::ProvingTask;

pub mod util;
