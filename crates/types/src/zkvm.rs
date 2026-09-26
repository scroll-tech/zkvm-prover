use once_cell::sync::Lazy;
use openvm_sdk::Sdk;
use openvm_sdk::config::AggregationSystemParams;
use openvm_sdk::keygen::SdkCachedProvingKey;
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_sdk::config::{
    MAX_APP_LOG_STACKED_HEIGHT, app_params_with_100_bits_security,
    internal_params_with_100_bits_security, leaf_params_with_100_bits_security,
};

/// Cached proving keys for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
///
/// Starting with OpenVM develop-v2.1.0, the SDK builder requires both `app_pk`
/// and `agg_pk` to be supplied together when seeding with pre-generated keys,
/// so we cache the full [`SdkCachedProvingKey`] instead of only `AggProvingKey`.
pub static AGG_STARK_PROVING_KEY: Lazy<SdkCachedProvingKey<SdkVmConfig>> = Lazy::new(build_agg_pk);

fn build_agg_pk() -> SdkCachedProvingKey<SdkVmConfig> {
    let app_params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };
    let sdk = Sdk::riscv64(app_params, agg_params);
    SdkCachedProvingKey {
        app_pk: sdk.app_pk().clone(),
        agg_pk: sdk.agg_pk(),
        deferral_pk: None,
        deferral_agg_pk: None,
        root_pk: None,
    }
}
