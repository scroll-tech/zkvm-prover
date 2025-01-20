pub mod chunk;

/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
pub trait ProvingTask {
    fn identifier(&self) -> String;
}
