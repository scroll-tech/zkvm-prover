use alloy_primitives::B256;

pub mod v3;

/// Reference header indicate the version of batch header base on which batch hash
/// should be calculated.
#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub enum ReferenceHeader {
    /// Represents DA-codec v3.
    V3(v3::BatchHeaderV3),
}

pub trait BatchHeader {
    fn version(&self) -> u8;

    fn index(&self) -> u64;

    fn batch_hash(&self) -> B256;
}
