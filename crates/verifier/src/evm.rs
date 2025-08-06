use openvm_sdk::types::EvmProof;
use openvm_sdk::types::EvmProof;
// Re-export from snark_verifier_sdk.
pub use snark_verifier_sdk::{
    evm::gen_evm_verifier_shplonk as gen_evm_verifier,
    halo2::aggregation as halo2_aggregation,
    snark_verifier::halo2_base::halo2_proofs::{
        SerdeFormat,
        halo2curves::bn256::{Fr, G1Affine},
        plonk::{Circuit, VerifyingKey},
    },
};

/// Serialize vk, code extracted from legacy prover.
pub fn serialize_vk(vk: &VerifyingKey<G1Affine>) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    vk.write(&mut result, SerdeFormat::Processed).unwrap();
    result
}

/// Deserialize vk, code extracted from legacy prover.
///
/// Panics if the deserialization fails.
pub fn deserialize_vk<C: Circuit<Fr, Params = ()>>(raw_vk: &[u8]) -> VerifyingKey<G1Affine> {
    VerifyingKey::<G1Affine>::read::<_, C>(
        &mut std::io::Cursor::new(raw_vk),
        SerdeFormat::Processed,
        (),
    )
    .unwrap_or_else(|_| panic!("failed to deserialize vk with len {}", raw_vk.len()))
}

/// Deploys the [`EvmVerifier`] contract and simulates an on-chain verification of the
/// [`EvmProof`].
///
/// This approach essentially simulates 2 txs:
/// - Deploy [`EvmVerifier`].
/// - Verify [`EvmProof`] encoded as calldata.
pub fn verify_evm_proof(evm_verifier: &[u8], evm_proof: &EvmProof) -> Result<u64, String> {
    let evm_proof: RawEvmProof = evm_proof
        .clone()
        .try_into()
        .map_err(|e| format!("Failed to convert EvmProof to RawEvmProof: {}", e))?;
    snark_verifier_sdk::snark_verifier::loader::evm::deploy_and_call(
        evm_verifier.to_vec(),
        evm_proof.verifier_calldata(),
    )
}

#[ignore = "need release assets"]
#[test]
fn test_verify_evm_proof() -> eyre::Result<()> {
    use std::path::Path;

    use crate::test::WrappedProof;

    const PATH_TESTDATA: &str = "./testdata";

    let evm_proof = WrappedProof::from_json(
        Path::new(PATH_TESTDATA)
            .join("proofs")
            .join("bundle-proof-phase2.json"),
    )?
    .proof;

    let evm_verifier: Vec<u8> =
        scroll_zkvm_prover::utils::read(Path::new(PATH_TESTDATA).join("verifier.bin"))?;

    let gas_cost = verify_evm_proof(&evm_verifier, &evm_proof.into_evm_proof().unwrap().into())
        .map_err(|e| eyre::eyre!("evm-proof verification failed: {e}"))?;

    println!("evm-verify gas cost = {gas_cost}");

    Ok(())
}
