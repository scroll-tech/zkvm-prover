use openvm_native_recursion::halo2::utils::{CacheHalo2ParamsReader, Halo2ParamsReader};
use openvm_sdk::{DefaultStaticVerifierPvHandler, Sdk, config::AggConfig};
use revm::{
    Context, Evm, Handler, InMemoryDB,
    primitives::{
        B256, Bytes, ExecutionResult, Output, TxEnv, TxKind, keccak256, specification::CancunSpec,
    },
};

/// The default directory to locate openvm's halo2 SRS parameters.
const DEFAULT_PARAMS_DIR: &str = concat!(env!("HOME"), "/.openvm/params/");

/// Generate and return the EVM PLONK verifier's initcode.
fn generate() -> eyre::Result<Vec<u8>> {
    let halo2_params_reader = CacheHalo2ParamsReader::new(DEFAULT_PARAMS_DIR);

    let agg_pk = Sdk::new().agg_keygen(
        AggConfig::default(),
        &halo2_params_reader,
        &DefaultStaticVerifierPvHandler,
    )?;

    let halo2_params =
        halo2_params_reader.read_params(agg_pk.halo2_pk.wrapper.pinning.metadata.config_params.k);

    Ok(snark_verifier_sdk::evm::gen_evm_verifier_shplonk::<
        snark_verifier_sdk::halo2::aggregation::AggregationCircuit,
    >(
        &halo2_params,
        agg_pk.halo2_pk.wrapper.pinning.pk.get_vk(),
        agg_pk.halo2_pk.wrapper.pinning.metadata.num_pvs.clone(),
        None,
    ))
}

/// Simulate deployment of initialisation code to get the deployed code and codehash.
fn deploy(init_code: &[u8]) -> eyre::Result<(Bytes, B256)> {
    let mut evm = Evm::new(
        Context::new_with_db(InMemoryDB::default()),
        Handler::mainnet::<CancunSpec>(),
    );

    *evm.tx_mut() = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TxKind::Create,
        data: init_code.to_vec().into(),
        ..Default::default()
    };

    let result = evm.transact_commit()?;
    let code = match result {
        ExecutionResult::Success {
            output: Output::Create(code, _),
            ..
        } => code,
        ExecutionResult::Revert { gas_used, output } => {
            return Err(eyre::eyre!(
                "Contract deployment tx reverted: gas_used={gas_used}, output={:#x}",
                output
            ));
        }
        ExecutionResult::Halt { reason, gas_used } => {
            return Err(eyre::eyre!(
                "Contract deployment tx halted unexpectedly: gas_used={gas_used}, reason={:?}",
                reason
            ));
        }
        _ => unreachable!(),
    };

    let codehash = keccak256(&code);

    Ok((code, codehash))
}

#[test]
fn export_onchain_verifier() -> eyre::Result<()> {
    let init_code = generate()?;

    let (deployed_code, codehash) = deploy(&init_code)?;

    println!("verifier.bin code len={}", deployed_code.len());
    println!("verifier.bin codehash={:?}", codehash);

    Ok(())
}
