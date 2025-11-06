use super::LOG_PREFIX;
use eyre::Result;
use openvm_native_recursion::halo2::utils::Halo2ParamsReader;
use openvm_sdk::Sdk;
use snark_verifier_sdk::SHPLONK;

pub fn generate_evm_verifier() -> Result<String> {
    let sdk = Sdk::riscv32();
    let halo2_params_reader = sdk.halo2_params_reader();
    let halo2_pk = sdk.halo2_pk();
    let halo2_params =
        halo2_params_reader.read_params(halo2_pk.wrapper.pinning.metadata.config_params.k);
    let sol_code = snark_verifier_sdk::evm::gen_evm_verifier_sol_code::<
        snark_verifier_sdk::halo2::aggregation::AggregationCircuit,
        SHPLONK,
    >(
        &halo2_params,
        halo2_pk.wrapper.pinning.pk.get_vk(),
        halo2_pk.wrapper.pinning.metadata.num_pvs.clone(),
    );

    // 1. write sol_code to a tmp file
    // 2. use `forge fmt $tmpfile` to format it
    // 3. read it out again, and assign the String as `sol_code`
    let temp_file = std::env::temp_dir().join("Halo2Verifier.sol");
    std::fs::write(&temp_file, &sol_code)?;

    let format_output = std::process::Command::new("forge")
        .arg("fmt")
        .arg(&temp_file)
        .output();

    let sol_code = match format_output {
        Ok(output) if output.status.success() => {
            println!("{LOG_PREFIX} Formatted verifier with forge fmt");
            std::fs::read_to_string(&temp_file)?
        }
        _ => {
            println!("{LOG_PREFIX} Warning: forge fmt failed, using unformatted code");
            sol_code
        }
    };

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_file);

    Ok(sol_code)
}

pub fn download_evm_verifier() -> Result<String> {
    let verifier_url = "https://github.com/openvm-org/openvm-solidity-sdk/raw/refs/heads/main/src/v1.4/Halo2Verifier.sol";
    println!("{LOG_PREFIX} Downloading pre-built verifier from openvm-solidity-sdk...");

    let output = std::process::Command::new("wget")
        .arg("-q")
        .arg("-O")
        .arg("-")
        .arg(verifier_url)
        .output()?;

    if !output.status.success() {
        return Err(eyre::eyre!(
            "Failed to download verifier from {}: wget exited with code {:?}",
            verifier_url,
            output.status.code()
        ));
    }

    println!("{LOG_PREFIX} Downloaded Halo2Verifier.sol");

    let sol_code = String::from_utf8(output.stdout)?;

    Ok(sol_code)
}
#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    #[test]
    fn test_verifier() {
        // assert `generate_evm_verifier` vs `download_evm_verifier` result are equal
        // if not, dump them to 2 files, and let user use vimdiff to check

        let num_preview_lines = 10;
        let print_verifier_info = |name: &str, code: &str| {
            println!("{} verifier length: {} bytes", name, code.len());
            let lines: Vec<&str> = code.lines().collect();
            for line in lines.iter().take(num_preview_lines) {
                println!("{}", line);
            }
            println!("...");
            for line in lines.iter().rev().take(num_preview_lines).rev() {
                println!("{}", line);
            }
        };

        let downloaded = download_evm_verifier().expect("Failed to download EVM verifier");
        print_verifier_info("Downloaded", &downloaded);

        let generated = generate_evm_verifier().expect("Failed to generate EVM verifier");
        print_verifier_info("Generated", &generated);

        if generated != downloaded {
            let temp_dir = std::env::temp_dir();
            let generated_file = temp_dir.join("generated_verifier.sol");
            let downloaded_file = temp_dir.join("downloaded_verifier.sol");

            fs::write(&generated_file, &generated).expect("Failed to write generated verifier");
            fs::write(&downloaded_file, &downloaded).expect("Failed to write downloaded verifier");

            panic!(
                "Verifiers are different! Compare files:\n  Generated: {}\n  Downloaded: {}\nUse: vimdiff {} {}",
                generated_file.display(),
                downloaded_file.display(),
                generated_file.display(),
                downloaded_file.display()
            );
        } else {
            println!("Verifiers match successfully!");
        }
    }
}
