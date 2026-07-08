//! Application-level post-processing for OpenVM-generated EVM verifier Solidity.
//!
//! OpenVM's upstream `OpenVmHalo2Verifier` template is written for rv32, where
//! each public-value cell is a single byte. On rv64 each cell is a 2-byte
//! little-endian u16 limb, so the wrapper must:
//!
//! 1. Receive `publicValues` as a byte array whose length is
//!    `PUBLIC_VALUES_LENGTH * PUBLIC_VALUES_LIMB_SIZE`.
//! 2. Reverse each little-endian limb into the high bytes of the corresponding
//!    32-byte Fr word (EVM interprets words as big-endian).
//!
//! This module transforms the upstream-generated wrapper into the rv64 format
//! without patching `openvm-sdk` itself.

use eyre::Result;

/// Post-process an rv32-oriented `OpenVmHalo2Verifier.sol` so that it supports
/// rv64 public-value limbs.
///
/// Returns the transformed Solidity source. The input must still contain the
/// upstream public-values copying logic.
pub fn post_process_openvm_verifier_for_rv64(sol_code: &str) -> Result<String> {
    // Extract the number of public-value limbs from the generated constant.
    let pvs_length = extract_public_values_length(sol_code)?;

    let mut out = sol_code.to_string();

    // 1. Update the PUBLIC_VALUES_LENGTH comment and add limb-size constants.
    out = out.replace(
        "/// @dev The length of the public values, in bytes. This value is set by\n    /// OpenVM and is guaranteed to be no larger than 8192.",
        "/// @dev The number of public value limbs exposed by the Halo2 circuit.\n    /// This value is set by OpenVM and is guaranteed to be no larger than 8192.",
    );

    let pvs_const = format!(
        "uint256 private constant PUBLIC_VALUES_LENGTH = {pvs_length};"
    );
    let pvs_const_replacement = format!(
        "{pvs_const}\n\n    /// @dev The byte width of each public value limb (1 for rv32, 2 for rv64).\n    uint256 private constant PUBLIC_VALUES_LIMB_SIZE = 2;\n\n    /// @dev The total byte length of the public values payload.\n    uint256 private constant PUBLIC_VALUES_BYTE_LENGTH = PUBLIC_VALUES_LENGTH * PUBLIC_VALUES_LIMB_SIZE;"
    );
    out = out.replace(&pvs_const, &pvs_const_replacement);

    // 2. Fix the length check in verify().
    out = out.replace(
        "if (publicValues.length != PUBLIC_VALUES_LENGTH) revert InvalidPublicValuesLength(PUBLIC_VALUES_LENGTH, publicValues.length);",
        "if (publicValues.length != PUBLIC_VALUES_BYTE_LENGTH) revert InvalidPublicValuesLength(PUBLIC_VALUES_BYTE_LENGTH, publicValues.length);",
    );

    // 3. Fix the doc comment in _constructProof that refers to bytes.
    out = out.replace(
        "/// proof[0x1c0..(0x1c0 + PUBLIC_VALUES_LENGTH * 32)]: publicValues[0..PUBLIC_VALUES_LENGTH]",
        "/// proof[0x1c0..(0x1c0 + PUBLIC_VALUES_LENGTH * 32)]: publicValue limbs[0..PUBLIC_VALUES_LENGTH]",
    );
    out = out.replace(
        "/// @param publicValues The PVs revealed by the OpenVM guest program.",
        "/// @param publicValues The PVs revealed by the OpenVM guest program. Each\n    /// public-value limb occupies PUBLIC_VALUES_LIMB_SIZE bytes in little-endian.",
    );

    // 4. Replace the public-values copying loop.
    // Upstream copies one byte per limb into offset 0x1f. We need to copy a
    // little-endian 2-byte limb into offsets 0x1e (high) and 0x1f (low).
    let old_loop = r#"// Copy each byte of the public values into the proof. It copies the
            // most significant bytes of public values first.
            let publicValuesMemOffset := add(add(proofPtr, 0x1c0), 0x1f)
            for { let i := 0 } iszero(eq(i, PUBLIC_VALUES_LENGTH)) { i := add(i, 1) } {
                calldatacopy(add(publicValuesMemOffset, shl(5, i)), add(publicValues.offset, i), 0x01)
            }"#;

    let new_loop = r#"// Copy each public-value limb into the low bytes of the corresponding
            // Fr slot. user_public_values stores limbs in little-endian, but each
            // 32-byte word is interpreted by the EVM as big-endian, so we reverse
            // the limb bytes as we copy them to the end of the word.
            for { let i := 0 } iszero(eq(i, PUBLIC_VALUES_LENGTH)) { i := add(i, 1) } {
                let wordPtr := add(proofPtr, add(0x1c0, shl(5, i)))
                // Clear the full word first; only the low bytes are overwritten.
                mstore(wordPtr, 0)
                for { let j := 0 } iszero(eq(j, PUBLIC_VALUES_LIMB_SIZE)) { j := add(j, 1) } {
                    // publicValues[i*LIMB_SIZE + j] is copied to the j-th byte
                    // from the end of the word, i.e. wordPtr + (0x1f - j).
                    calldatacopy(
                        add(wordPtr, sub(0x1f, j)),
                        add(publicValues.offset, add(mul(i, PUBLIC_VALUES_LIMB_SIZE), j)),
                        0x01
                    )
                }
            }"#;

    if !out.contains(old_loop) {
        return Err(eyre::eyre!(
            "upstream public-values loop not found; cannot post-process verifier.sol"
        ));
    }
    out = out.replace(old_loop, new_loop);

    Ok(out)
}

fn extract_public_values_length(sol_code: &str) -> Result<usize> {
    let re = regex::Regex::new(
        r"uint256\s+private\s+constant\s+PUBLIC_VALUES_LENGTH\s*=\s*(\d+)\s*;",
    )
    .unwrap();
    let caps = re
        .captures(sol_code)
        .ok_or_else(|| eyre::eyre!("PUBLIC_VALUES_LENGTH constant not found in verifier.sol"))?;
    let value: usize = caps[1]
        .parse()
        .map_err(|e| eyre::eyre!("failed to parse PUBLIC_VALUES_LENGTH: {e}"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_process_rv64() {
        let upstream = r#"// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract OpenVmHalo2Verifier {
    /// @dev The length of the public values, in bytes. This value is set by
    /// OpenVM and is guaranteed to be no larger than 8192.
    uint256 private constant PUBLIC_VALUES_LENGTH = 32;

    function verify(bytes calldata publicValues, bytes calldata proofData, bytes32 appExeCommit, bytes32 appVmCommit) external view {
        if (publicValues.length != PUBLIC_VALUES_LENGTH) revert InvalidPublicValuesLength(PUBLIC_VALUES_LENGTH, publicValues.length);
    }

    function _constructProof(bytes calldata publicValues, bytes calldata proofData, bytes32 appExeCommit, bytes32 appVmCommit)
        internal
        pure
        returns (MemoryPointer proofPtr)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // Copy each byte of the public values into the proof. It copies the
            // most significant bytes of public values first.
            let publicValuesMemOffset := add(add(proofPtr, 0x1c0), 0x1f)
            for { let i := 0 } iszero(eq(i, PUBLIC_VALUES_LENGTH)) { i := add(i, 1) } {
                calldatacopy(add(publicValuesMemOffset, shl(5, i)), add(publicValues.offset, i), 0x01)
            }
        }
    }
}
"#;

        let processed = post_process_openvm_verifier_for_rv64(upstream).unwrap();
        assert!(processed.contains("PUBLIC_VALUES_LIMB_SIZE = 2"));
        assert!(processed.contains("PUBLIC_VALUES_BYTE_LENGTH = PUBLIC_VALUES_LENGTH * PUBLIC_VALUES_LIMB_SIZE"));
        assert!(processed.contains("publicValues.length != PUBLIC_VALUES_BYTE_LENGTH"));
        assert!(processed.contains("add(wordPtr, sub(0x1f, j))"));
        assert!(!processed.contains("let publicValuesMemOffset := add(add(proofPtr, 0x1c0), 0x1f)"));
    }
}
