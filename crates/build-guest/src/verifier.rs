use super::LOG_PREFIX;
use eyre::Result;

/// Download a pre-built Solidity verifier from `openvm-solidity-sdk`.
///
/// # Note
/// The version string below tracks the **solidity-sdk** release tag, not the
/// `openvm` crate version. Keep it in sync with the `openvm-solidity-sdk`
/// revision used by the pinned `openvm` crates.
pub fn download_evm_verifier() -> Result<openvm_sdk::types::EvmHalo2Verifier> {
    // The `openvm-solidity-sdk` release tag to download from. This is NOT the
    // same as the `openvm` crate version; the SDK follows its own tagging.
    let solidity_sdk_tag = "v2.0";
    // We generate/download the bundle (deferral-enabled) verifier. The plain
    // `v2.0-base` verifier is used for leaf circuits that do not defer proof
    // verification.
    let verifier_path = "v2.0-deferral";
    let verifier_url = format!(
        "https://raw.githubusercontent.com/openvm-org/openvm-solidity-sdk/{solidity_sdk_tag}/src/{verifier_path}/OpenVmHalo2Verifier.sol"
    );
    let interface_url = format!(
        "https://raw.githubusercontent.com/openvm-org/openvm-solidity-sdk/{solidity_sdk_tag}/src/{verifier_path}/interfaces/IOpenVmHalo2Verifier.sol"
    );
    let halo2_url = format!(
        "https://raw.githubusercontent.com/openvm-org/openvm-solidity-sdk/{solidity_sdk_tag}/src/{verifier_path}/Halo2Verifier.sol"
    );
    println!(
        "{LOG_PREFIX} Downloading pre-built verifier from openvm-solidity-sdk (tag {solidity_sdk_tag}, path {verifier_path})..."
    );

    let fetch = |url: &str| -> Result<String> {
        let output = std::process::Command::new("wget")
            .arg("-q")
            .arg("-O")
            .arg("-")
            .arg(url)
            .output()?;
        if !output.status.success() {
            return Err(eyre::eyre!(
                "Failed to download {}: wget exited with code {:?}",
                url,
                output.status.code()
            ));
        }
        Ok(String::from_utf8(output.stdout)?)
    };

    let sol_code = fetch(&verifier_url)?;
    let halo2_code = fetch(&halo2_url)?;
    let interface_code = fetch(&interface_url)?;

    println!("{LOG_PREFIX} Downloaded OpenVmHalo2Verifier.sol");

    Ok(openvm_sdk::types::EvmHalo2Verifier {
        halo2_verifier_code: halo2_code,
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
    use std::{fs, path::Path};

    /// Format Solidity source with `forge fmt` and return the normalized code.
    ///
    /// We compare the *formatted* source rather than raw bytes because the SDK
    /// download and the local generator may use different formatting styles.
    fn format_with_forge(code: &str, file_name: &str) -> String {
        let temp_dir = std::env::temp_dir().join(format!(
            "scroll-zkvm-forge-fmt-{}-{}",
            std::process::id(),
            file_name
        ));
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir for forge fmt");
        let file_path = temp_dir.join(file_name);

        fs::write(&file_path, code).expect("Failed to write temp Solidity file");

        let output = std::process::Command::new("forge")
            .arg("fmt")
            .arg(&file_path)
            .output()
            .expect("Failed to run `forge fmt`. Is Foundry installed?");

        if !output.status.success() {
            panic!(
                "`forge fmt` failed for {}: {}",
                file_name,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fs::read_to_string(&file_path).expect("Failed to read formatted Solidity file")
    }

    /// Compare downloaded and locally generated EVM verifier Solidity sources.
    ///
    /// This test is ignored by default because it builds the full bundle SDK
    /// verifier, which is slow. Run it explicitly with:
    /// `cargo test --release -p scroll-zkvm-build-guest test_verifier -- --ignored`
    #[test]
    #[ignore = "slow: builds full bundle SDK verifier"]
    fn test_verifier() {
        let downloaded = download_evm_verifier().expect("Failed to download EVM verifier");
        let generated = {
            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
            let release_output_dir = workspace_root.join("releases/dev");
            crate::build_evm_verifier(&release_output_dir)
                .expect("Failed to generate EVM verifier")
                .1
        };

        let cases = [
            (
                "OpenVmHalo2Verifier",
                "OpenVmHalo2Verifier.sol",
                &generated.openvm_verifier_code,
                &downloaded.openvm_verifier_code,
            ),
            (
                "Halo2Verifier",
                "Halo2Verifier.sol",
                &generated.halo2_verifier_code,
                &downloaded.halo2_verifier_code,
            ),
            (
                "IOpenVmHalo2Verifier",
                "IOpenVmHalo2Verifier.sol",
                &generated.openvm_verifier_interface,
                &downloaded.openvm_verifier_interface,
            ),
        ];

        for (name, file_name, gen, dl) in cases {
            println!(
                "Comparing {name} (generated {} bytes vs downloaded {} bytes)",
                gen.len(),
                dl.len()
            );
            let gen_fmt = format_with_forge(gen, file_name);
            let dl_fmt = format_with_forge(dl, file_name);
            assert_eq!(
                gen_fmt, dl_fmt,
                "{name} differs between locally generated and downloaded verifier"
            );
            println!("{name} matches after formatting");
        }
    }
}
