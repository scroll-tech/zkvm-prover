mod crypto;
pub use crypto::Crypto;

#[cfg(feature = "scroll")]
pub mod scroll;

#[cfg(not(feature = "scroll"))]
pub mod ethereum;
