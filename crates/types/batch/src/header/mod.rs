use alloy_primitives::B256;

pub mod v6;

pub mod v7;

pub mod v8;

pub mod validium;

pub trait BatchHeader {
    /// The DA-codec version for the batch header.
    fn version(&self) -> u8;

    /// The incremental index of the batch.
    fn index(&self) -> u64;

    /// The batch header digest of the parent batch.
    fn parent_batch_hash(&self) -> B256;

    /// The batch header digest.
    fn batch_hash(&self) -> B256;

    /// The blob-versioned hash as per EIP-4844 for the blob representing the batch.
    fn blob_versioned_hash(&self) -> B256;
}

pub trait ValidiumBatchHeader: BatchHeader {
    /// The commitment attached to the batch header.
    fn commitment(&self) -> Vec<u8>;

    /// The state root after applying batch.
    fn post_state_root(&self) -> B256;

    /// The withdraw root from the last block in the batch.
    fn withdraw_root(&self) -> B256;
}

/// Reference header indicate the version of batch header base on which batch hash
/// should be calculated.
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
pub enum ReferenceHeader {
    /// Represents DA-codec v6.
    V6(v6::BatchHeaderV6),
    /// Represents DA-codec v7.
    V7(v7::BatchHeaderV7),
    /// Represents DA-codec v8.
    V8(v8::BatchHeaderV8),
    /// Represents batch header utilised in L3 validium.
    Validium(validium::BatchHeaderValidium),
}
