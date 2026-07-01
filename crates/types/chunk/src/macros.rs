/// Mirrors `sbv_helpers::manually_drop_on_zkvm!` but uses `core::mem::ManuallyDrop`
/// so it works in `no_std` SP1 guests.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
macro_rules! manually_drop_on_zkvm {
    ($e:expr) => {
        core::mem::ManuallyDrop::new($e)
    };
}

/// On native hosts the wrapper is a no-op so drops run normally.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! manually_drop_on_zkvm {
    ($e:expr) => {
        $e
    };
}
