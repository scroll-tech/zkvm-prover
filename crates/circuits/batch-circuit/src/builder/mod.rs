#[cfg(not(feature = "euclidv2"))]
pub mod v3;
#[cfg(not(feature = "euclidv2"))]
pub use v3::BatchInfoBuilderV3 as BatchInfoBuilder;

#[cfg(feature = "euclidv2")]
pub mod v7;
#[cfg(feature = "euclidv2")]
pub use v7::BatchInfoBuilderV7 as BatchInfoBuilder;
