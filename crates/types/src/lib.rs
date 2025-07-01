// re-export for a compatible interface with old circuit/types for prover

pub mod bundle {
    pub use types_base::public_inputs::bundle::BundleInfo;
    pub use types_bundle::*;

    pub struct ToArchievedWitness(pub rkyv::util::AlignedVec);
    impl ToArchievedWitness {
        pub fn create(witness: &BundleWitness) -> Result<Self, String> {
            rkyv::to_bytes::<rkyv::rancor::Error>(witness)
                .map_err(|e| format!("failed to serialize bundle witness: {e}"))
                .map(Self)
        }
        pub fn access(&self) -> Result<&ArchivedBundleWitness, String> {
            rkyv::access::<ArchivedBundleWitness, rkyv::rancor::BoxedError>(&self.0)
                .map_err(|e| format!("rkyv deserialisation of bundle witness bytes failed: {e}"))
        }
    }
}

pub mod batch {
    pub use types_base::public_inputs::batch::{ArchivedBatchInfo, BatchInfo, VersionedBatchInfo};
    pub use types_batch::*;

    pub struct ToArchievedWitness(pub rkyv::util::AlignedVec);
    impl ToArchievedWitness {
        pub fn create(witness: &BatchWitness) -> Result<Self, String> {
            rkyv::to_bytes::<rkyv::rancor::Error>(witness)
                .map_err(|e| format!("failed to serialize batch witness: {e}"))
                .map(Self)
        }
        pub fn access(&self) -> Result<&ArchivedBatchWitness, String> {
            rkyv::access::<ArchivedBatchWitness, rkyv::rancor::BoxedError>(&self.0)
                .map_err(|e| format!("rkyv deserialisation of batch witness bytes failed: {e}"))
        }
    }
}

pub mod chunk {
    pub use types_base::public_inputs::chunk::{
        ArchivedChunkInfo, BlockContextV2, ChunkInfo, SIZE_BLOCK_CTX, VersionedChunkInfo,
    };
    pub use types_chunk::*;

    pub struct ToArchievedWitness(pub rkyv::util::AlignedVec);
    impl ToArchievedWitness {
        pub fn create(witness: &ChunkWitness) -> Result<Self, String> {
            rkyv::to_bytes::<rkyv::rancor::Error>(witness)
                .map_err(|e| format!("failed to serialize chunk witness: {e}"))
                .map(Self)
        }
        pub fn access(&self) -> Result<&ArchivedChunkWitness, String> {
            rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(&self.0)
                .map_err(|e| format!("rkyv deserialisation of chunk witness bytes failed: {e}"))
        }
    }
}

pub use types_base::{aggregation as types_agg, environ, public_inputs, utils};

pub mod proof;

pub mod task;
pub use task::ProvingTask;

pub mod util;
