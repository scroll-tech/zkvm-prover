pub mod batch;

pub mod chunk;

pub mod bundle;

/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
pub trait ProvingTask {
    fn identifier(&self) -> String;

    fn to_witness_serialized(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error>;
}
