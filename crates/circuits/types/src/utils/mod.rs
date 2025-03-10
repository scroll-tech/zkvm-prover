mod hash;
pub use hash::{keccak256, keccak256_rv32};

mod io;
pub use io::read_witnesses;

#[macro_export]
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
macro_rules! manually_drop_on_zkvm {
    ($e:expr) => {
        std::mem::ManuallyDrop::new($e)
    };
}

#[macro_export]
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! manually_drop_on_zkvm {
    ($e:expr) => {
        $e
    };
}
