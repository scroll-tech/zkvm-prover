#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm::platform as openvm_platform;

/// Read the witnesses from the hint stream.
pub fn read_witnesses() -> Vec<u8> {
    openvm::io::read_vec()
}
