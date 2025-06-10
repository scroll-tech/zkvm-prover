use openvm_sdk::StdIn;
use scroll_zkvm_types::public_inputs::ForkName;

pub mod batch;

pub mod chunk;

pub mod bundle;

/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
pub trait ProvingTask: serde::de::DeserializeOwned {
    fn identifier(&self) -> String;

    fn build_guest_input(&self) -> Result<StdIn, rkyv::rancor::Error>;

    fn fork_name(&self) -> ForkName;
}
