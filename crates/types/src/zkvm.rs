use once_cell::sync::Lazy;
use openvm_sdk::Sdk;
use openvm_sdk::keygen::AggProvingKey;

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
pub static AGG_STARK_PROVING_KEY: Lazy<AggProvingKey> = Lazy::new(|| build_agg_pk());

fn build_agg_pk() -> AggProvingKey {
    Sdk::riscv32().agg_pk().clone()
}
