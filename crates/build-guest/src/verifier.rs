use super::LOG_PREFIX;
use eyre::Result;

/// Download a pre-built Solidity verifier from `openvm-solidity-sdk`.
///
/// # Note
/// The version string below tracks the **solidity-sdk** release tag, not the
/// `openvm` crate version. Keep it in sync with the `openvm-solidity-sdk`
/// revision used by the pinned `openvm` crates.
pub fn download_evm_verifier() -> Result<openvm_sdk::types::EvmHalo2Verifier> {
    let openvm_version = "v2.0.0-rc.3";
    let verifier_url = format!(
        "https://github.com/openvm-org/openvm-solidity-sdk/raw/refs/heads/main/src/{openvm_version}/OpenVmHalo2Verifier.sol"
    );
    let interface_url = format!(
        "https://github.com/openvm-org/openvm-solidity-sdk/raw/refs/heads/main/src/{openvm_version}/IOpenVmHalo2Verifier.sol"
    );
    println!("{LOG_PREFIX} Downloading pre-built verifier from openvm-solidity-sdk...");

    let sol_output = std::process::Command::new("wget")
        .arg("-q")
        .arg("-O")
        .arg("-")
        .arg(&verifier_url)
        .output()?;

    if !sol_output.status.success() {
        return Err(eyre::eyre!(
            "Failed to download verifier from {}: wget exited with code {:?}",
            verifier_url,
            sol_output.status.code()
        ));
    }

    let interface_output = std::process::Command::new("wget")
        .arg("-q")
        .arg("-O")
        .arg("-")
        .arg(&interface_url)
        .output()?;

    if !interface_output.status.success() {
        return Err(eyre::eyre!(
            "Failed to download interface from {}: wget exited with code {:?}",
            interface_url,
            interface_output.status.code()
        ));
    }

    println!("{LOG_PREFIX} Downloaded OpenVmHalo2Verifier.sol");

    // In download mode we don't have bytecode, return empty artifact
    let sol_code = String::from_utf8(sol_output.stdout)?;
    let interface_code = String::from_utf8(interface_output.stdout)?;

    Ok(openvm_sdk::types::EvmHalo2Verifier {
        halo2_verifier_code: String::new(),
        openvm_verifier_code: sol_code,
        openvm_verifier_interface: interface_code,
        artifact: openvm_static_verifier::wrapper::EvmVerifierByteCode {
            sol_compiler_version: String::new(),
            sol_compiler_options: String::new(),
            bytecode: Vec::new(),
        },
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires openvm-solidity-sdk to publish v2 verifier (currently unavailable)"]
    fn test_verifier() {
        // Smoke-test: ensure the download URL is still reachable and returns
        // non-empty Solidity code.  A full "generate vs download" comparison
        // requires a full SDK setup and is exercised in CI instead.
        //
        // Note: As of OpenVM v2.0.0-rc.3, the solidity-sdk repo only has
        // v1.x tags.  Use RECOMPUTE_MODE=yes to generate the verifier locally.

        let downloaded = download_evm_verifier().expect("Failed to download EVM verifier");
        assert!(
            !downloaded.openvm_verifier_code.is_empty(),
            "downloaded verifier code is empty"
        );
        println!(
            "Downloaded verifier length: {} bytes",
            downloaded.openvm_verifier_code.len()
        );
    }
}
