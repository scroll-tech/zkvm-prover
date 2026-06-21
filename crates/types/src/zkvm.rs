use once_cell::sync::Lazy;
use openvm_sdk::Sdk;
use openvm_sdk::keygen::AggProvingKey;
use openvm_sdk::config::AggregationSystemParams;
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security,
    leaf_params_with_100_bits_security,
    internal_params_with_100_bits_security,
    MAX_APP_LOG_STACKED_HEIGHT,
};

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
pub static AGG_STARK_PROVING_KEY: Lazy<AggProvingKey> = Lazy::new(build_agg_pk);

fn build_agg_pk() -> AggProvingKey {
    let app_params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };
    Sdk::riscv64(app_params, agg_params).agg_pk().clone()
}
