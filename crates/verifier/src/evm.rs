use openvm_native_recursion::halo2::{EvmProof, wrapper::EvmVerifier};
use revm::{
    Context, Evm, Handler, InMemoryDB,
    primitives::{ExecutionResult, Output, TransactTo, TxEnv, TxKind, specification::CancunSpec},
};

pub use snark_verifier_sdk::{
    evm::gen_evm_verifier_shplonk as gen_evm_verifier, halo2::aggregation as halo2_aggregation,
};

/// A helper function for testing to verify the proof of this circuit with evm verifier.
/// extract from openvm's halo2 wrapper
pub fn evm_verify(evm_verifier: &EvmVerifier, evm_proof: &EvmProof) {
    let calldata = snark_verifier_sdk::evm::encode_calldata(&evm_proof.instances, &evm_proof.proof);
    let gas_cost = deploy_and_call(evm_verifier.0.clone(), calldata).unwrap();
    dbg!(gas_cost);
}

/// copy the file in openvm_sdk
pub fn verify_evm_proof(evm_verifier: &EvmVerifier, evm_proof: &EvmProof) -> bool {
    std::panic::catch_unwind(|| {
        evm_verify(evm_verifier, evm_proof);
    })
    .is_ok()
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

    let evm_verifier = scroll_zkvm_prover::utils::read(
        Path::new(PATH_TESTDATA)
            .join("verifier")
            .join("verifier.bin"),
    )?;

    let calldata = snark_verifier_sdk::evm::encode_calldata(
        &evm_proof.proof.instances,
        &evm_proof.proof.proof,
    );
    // snark_verifier_sdk::evm::evm_verify(
    //     evm_verifier,
    //     evm_proof.proof.instances,
    //     evm_proof.proof.proof,
    // );
    let gas_cost = deploy_and_call(evm_verifier, calldata).unwrap();
    dbg!(gas_cost);

    Ok(())
}
