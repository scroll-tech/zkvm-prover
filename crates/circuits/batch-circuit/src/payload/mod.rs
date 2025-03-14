#[cfg(not(feature = "euclidv2"))]
pub mod v3;
#[cfg(feature = "euclidv2")]
pub mod v7;
