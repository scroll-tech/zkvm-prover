use openvm_native_recursion::halo2::{EvmProof, wrapper::EvmVerifier};
use revm::{
    Context, Evm, Handler, InMemoryDB,
    primitives::{ExecutionResult, Output, TransactTo, TxEnv, TxKind, specification::CancunSpec},
};

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
pub fn verify_evm_proof(evm_verifier: &EvmVerifier, evm_proof: &EvmProof) -> Result<u64, String> {
    let calldata = snark_verifier_sdk::evm::encode_calldata(&evm_proof.instances, &evm_proof.proof);
    deploy_and_call(evm_verifier.0.clone(), calldata)
}

fn deploy_and_call(deployment_code: Vec<u8>, calldata: Vec<u8>) -> Result<u64, String> {
    let mut evm = Evm::new(
        Context::new_with_db(InMemoryDB::default()),
        Handler::mainnet::<CancunSpec>(),
    );

    *evm.tx_mut() = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TxKind::Create,
        data: deployment_code.into(),
        ..Default::default()
    };

    let result = evm.transact_commit().unwrap();
    let contract = match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(contract)),
            ..
        } => contract,
        ExecutionResult::Revert { gas_used, output } => {
            return Err(format!(
                "Contract deployment transaction reverts with gas_used {gas_used} and output {:#x}",
                output
            ));
        }
        ExecutionResult::Halt { reason, gas_used } => {
            return Err(format!(
                "Contract deployment transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
                reason
            ));
        }
        _ => unreachable!(),
    };

    *evm.tx_mut() = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TransactTo::Call(contract),
        data: calldata.into(),
        ..Default::default()
    };

    let result = evm.transact_commit().unwrap();
    match result {
        ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
        ExecutionResult::Revert { gas_used, output } => Err(format!(
            "Contract call transaction reverts with gas_used {gas_used} and output {:#x}",
            output
        )),
        ExecutionResult::Halt { reason, gas_used } => Err(format!(
            "Contract call transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
            reason
        )),
    }
}

#[test]
fn test_verify_evm_proof() -> eyre::Result<()> {
    use scroll_zkvm_prover::{BundleProof, utils::read_json_deep};
    use std::path::Path;

    const PATH_TESTDATA: &str = "../integration/testdata";

    let evm_proof = read_json_deep::<_, BundleProof>(Path::new(PATH_TESTDATA).join("proofs").join("bundle-0x60f88f3e46c74362cd93c07724c9ef8e56e391317df6504b905c3c16e81de2e4-0x30d2f51e20e9a4ecd460466af9c81d13daad4fb8d1ca1e42dab30603374f7e5f.json"))?;

    let evm_verifier = EvmVerifier(scroll_zkvm_prover::utils::read(
        Path::new(PATH_TESTDATA)
            .join("verifier")
            .join("verifier.bin"),
    )?);

    let gas_cost = verify_evm_proof(&evm_verifier, &evm_proof.as_proof())
        .map_err(|e| eyre::eyre!("evm-proof verification failed: {e}"))?;

    println!("evm-verify gas cost = {gas_cost}");

    Ok(())
}
