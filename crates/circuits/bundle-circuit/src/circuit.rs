use crate::child_commitments::{EXE_COMMIT as BATCH_EXE_COMMIT, LEAF_COMMIT as BATCH_LEAF_COMMIT};
use alloy_primitives::B256;
use scroll_zkvm_types_bundle::ArchivedBundleWitness;
use scroll_zkvm_types_circuit::{
    AggCircuit, AggregationInput, Circuit, ProgramCommitment,
    io::read_witnesses,
    public_inputs::{
        ForkName, PublicInputs,
        batch::VersionedBatchInfo,
        bundle::{BundleInfo, BundleInfoV1, BundleInfoV2},
    },
};

#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm_keccak256_guest;

#[derive(Default)]
pub struct BundleCircuit<T>(std::marker::PhantomData<T>);

impl<T: PublicInputs + From<BundleInfo>> Circuit for BundleCircuit<T> {
    type Witness = ArchivedBundleWitness;

    type PublicInputs = T;

    fn setup() {}

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness {
        rkyv::access::<ArchivedBundleWitness, rkyv::rancor::BoxedError>(witness_bytes)
            .expect("BundleCircuit: rkyv deserialization of witness bytes failed")
    }

    fn validate(witness: &Self::Witness) -> Self::PublicInputs {
        assert!(
            !witness.batch_infos.is_empty(),
            "at least one batch in a bundle"
        );

        let (first_batch, last_batch) = (
            witness
                .batch_infos
                .first()
                .expect("at least one batch in bundle"),
            witness
                .batch_infos
                .last()
                .expect("at least one batch in bundle"),
        );

        let chain_id = first_batch.chain_id.into();
        let num_batches = u32::try_from(witness.batch_infos.len()).expect("num_batches: u32");
        let prev_state_root = first_batch.parent_state_root.into();
        let prev_batch_hash = first_batch.parent_batch_hash.into();
        let post_state_root = last_batch.state_root.into();
        let batch_hash = last_batch.batch_hash.into();
        let withdraw_root = last_batch.withdraw_root.into();
        let msg_queue_hash = last_batch.post_msg_queue_hash.into();

        BundleInfo {
            chain_id,
            num_batches,
            prev_state_root,
            prev_batch_hash,
            post_state_root,
            batch_hash,
            withdraw_root,
            msg_queue_hash,
        }
        .into()
    }
}

pub trait ForkNameInfo {
    fn fork_name() -> ForkName;
}

impl ForkNameInfo for BundleInfoV1 {
    fn fork_name() -> ForkName {
        ForkName::EuclidV1
    }
}

impl ForkNameInfo for BundleInfoV2 {
    fn fork_name() -> ForkName {
        ForkName::EuclidV2
    }
}

impl<T: ForkNameInfo + PublicInputs + From<BundleInfo>> AggCircuit for BundleCircuit<T> {
    type AggregatedPublicInputs = VersionedBatchInfo;

    fn verify_commitments(commitment: &ProgramCommitment) {
        assert_eq!(
            commitment.exe, BATCH_EXE_COMMIT,
            "mismatch batch-proof exe commitment: expected={:?}, got={:?}",
            BATCH_EXE_COMMIT, commitment.exe,
        );
        assert_eq!(
            commitment.leaf, BATCH_LEAF_COMMIT,
            "mismatch batch-proof leaf commitment: expected={:?}, got={:?}",
            BATCH_LEAF_COMMIT, commitment.leaf,
        );
    }

    fn aggregated_public_inputs(witness: &Self::Witness) -> Vec<Self::AggregatedPublicInputs> {
        witness
            .batch_infos
            .iter()
            .map(|archived| (archived.into(), T::fork_name()))
            .collect()
    }

    fn aggregated_pi_hashes(proofs: &[AggregationInput]) -> Vec<B256> {
        proofs
            .iter()
            .map(|proof| {
                let transformed = proof
                    .public_values
                    .iter()
                    .map(|&val| u8::try_from(val).expect("0 < public value < 256"))
                    .collect::<Vec<u8>>();
                B256::from_slice(transformed.as_slice())
            })
            .collect()
    }
}
