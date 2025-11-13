// This should be removed after we fully migrated to openvm 1.4 after protoco upgrade.
use once_cell::sync::Lazy;
use openvm_sdk::Sdk;
use openvm_sdk::keygen::AggProvingKey;
use std::sync::Arc;

mod openvm_private_patch {
    // copied from openvm/crates/sdk/src/keygen/perm.rs
    use std::cmp::Reverse;

    /// Permutation of the AIR IDs to order them by forced trace heights.
    pub(crate) struct AirIdPermutation {
        pub perm: Vec<usize>,
    }

    impl AirIdPermutation {
        pub fn compute(heights: &[u32]) -> AirIdPermutation {
            let mut height_with_air_id: Vec<_> = heights.iter().copied().enumerate().collect();
            height_with_air_id.sort_by_key(|(_, h)| Reverse(*h));
            AirIdPermutation {
                perm: height_with_air_id
                    .into_iter()
                    .map(|(a_id, _)| a_id)
                    .collect(),
            }
        }
        /// arr[i] <- arr[perm[i]]
        pub(crate) fn permute<T>(&self, arr: &mut [T]) {
            debug_assert_eq!(arr.len(), self.perm.len());
            let mut perm = self.perm.clone();
            for i in 0..perm.len() {
                if perm[i] != i {
                    let mut curr = i;
                    loop {
                        let target = perm[curr];
                        perm[curr] = curr;
                        if perm[target] == target {
                            break;
                        }
                        arr.swap(curr, target);
                        curr = target;
                    }
                }
            }
        }
    }
}

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
pub static AGG_STARK_PROVING_KEY: Lazy<AggProvingKey> = Lazy::new(|| build_agg_pk(false));
pub static AGG_STARK_PROVING_KEY_V13: Lazy<AggProvingKey> = Lazy::new(|| build_agg_pk(true));

fn build_agg_pk(legacy_v13: bool) -> AggProvingKey {
    let mut agg_pk = Sdk::riscv32().agg_pk().clone();
    if !legacy_v13 {
        // it is a bit confusing..
        // we plan to enable `feature = "legacy-v1-3-evm-verifier"`,
        // so here we need to mimic v14 behavior
        let root_air_perm =
            openvm_private_patch::AirIdPermutation::compute(&agg_pk.root_verifier_pk.air_heights);
        let vm_pk = Arc::get_mut(&mut agg_pk.root_verifier_pk.vm_pk).unwrap();
        for thc in &mut vm_pk.vm_pk.trace_height_constraints {
            root_air_perm.permute(&mut thc.coefficients);
        }
    }

    agg_pk
}
