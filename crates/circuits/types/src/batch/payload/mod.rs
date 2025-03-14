#[cfg(not(feature = "euclidv2"))]
pub mod v3;
#[cfg(feature = "euclidv2")]
pub mod v7;

/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
pub const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;

/// The number of BLS12-381 scalar fields that effectively represent an EIP-4844 blob.
pub const BLOB_WIDTH: usize = 4096;

/// Base 2 logarithm of `BLOB_WIDTH`.
pub const LOG_BLOB_WIDTH: usize = 12;

/// The effective (reduced) number of bytes we can use within a blob.
///
/// EIP-4844 requires that each 32-bytes chunk of bytes represent a BLS12-381 scalar field element
/// in its canonical form. As a result, we set the most-significant byte in each such chunk to 0.
/// This allows us to use only up to 31 bytes in each such chunk, hence the reduced capacity.
pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;
