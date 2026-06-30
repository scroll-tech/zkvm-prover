#![cfg_attr(target_os = "zkvm", no_std)]
extern crate alloc;

#[macro_use]
mod macros;

#[cfg(feature = "openvm")]
mod crypto;
#[cfg(feature = "openvm")]
pub use crypto::Crypto;

#[cfg(feature = "scroll")]
pub mod scroll;

#[cfg(not(feature = "scroll"))]
pub mod ethereum;
