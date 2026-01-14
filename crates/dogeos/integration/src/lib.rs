use scroll_zkvm_integration::WORKSPACE_ROOT;
use std::path::Path;
use std::sync::LazyLock;
pub static DOGEOS_CRATES_ROOT: LazyLock<&Path> = LazyLock::new(|| {
    Box::leak(
        WORKSPACE_ROOT
            .join("crates")
            .join("dogeos")
            .into_boxed_path(),
    )
});
pub static DOGEOS_INTEGRATION_ROOT: LazyLock<&Path> =
    LazyLock::new(|| Box::leak(DOGEOS_CRATES_ROOT.join("integration").into_boxed_path()));
pub static DOGEOS_TESTDATA_ROOT: LazyLock<&Path> =
    LazyLock::new(|| Box::leak(DOGEOS_INTEGRATION_ROOT.join("testdata").into_boxed_path()));

pub mod testers;
